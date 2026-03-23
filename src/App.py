import asyncio
import struct
import random
from fastapi import FastAPI, HTTPException, Form
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import uvicorn
import secrets
import hmac
import hashlib
import base64

# --- STATE MANAGEMENT ---
rooms: dict[int, str] = {}
cpp_writer: asyncio.StreamWriter | None = None
# Maps UID -> asyncio.Event to notify the HTTP handler when C++ sends an ACK
pending_acks: dict[int, asyncio.Event] = {}
gen_acks: dict[int, asyncio.Event] = {}
user_queue: dict[str, asyncio.Event] = {}
tab2u: dict[str, int] = {}
SECRET_KEY = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[SYSTEM] Conclave Bridge starting...")
    app.state.conclave_task = asyncio.create_task(listen_to_conclave(app))
    yield
    print("[SYSTEM] Conclave Bridge shutting down...")
    app.state.conclave_task.cancel()
    try:
        await app.state.conclave_task
    except asyncio.CancelledError:
        pass
    if cpp_writer:
        cpp_writer.close()
        await cpp_writer.wait_closed()

app = FastAPI(title="Conclave", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")

# --- CORE COMMUNICATION ---

def ack_router(ack_type: int, data: bytes):
    global tab2u, gen_acks, user_queue
    """
    Handles ACKs from C++. 
    MessageType::ACK (3) is stripped in listen_to_conclave.
    data[0] is AckType (Connect=0, Join=1)
    """
    print(f"[ACK] Type: {ack_type}")

    if ack_type == 0: # Connect Ack (Reserved UID for a Tab)
        # C++ sends: [AckType(1)][UID(4)][TabID(N)]
        uid = struct.unpack('!I', data[0:4])[0]
        ack_id = data[5:].decode('utf-8')
        print(f"Trying to connect user on Tab: {ack_id}")
        if ack_id in user_queue:
            print(f"[ACK] Reserved UID {uid} for TAB: {ack_id}")
            tab2u[ack_id] = uid
            user_queue[ack_id].set()

    elif ack_type == 1: # Join Ack (Room Access Granted)
        # C++ sends: [AckType(1)][UID(4)]
        uid = struct.unpack('!I', data[0:4])[0]
        if uid in pending_acks:
            print(f"[ACK] Join confirmed for UID: {uid}")
            pending_acks[uid].set()
    elif ack_type == 2: #Generic ACK: True
        uid = struct.unpack('!I', data[0:4])[0]
        #print(f"[ACK] User: {uid} Code: {data[-1]}")
        if uid in gen_acks:
            if data[-1] == 0:  
                print(f"[ACK] Verified Access to ROOM for UID: {uid}")
                gen_acks[uid].set()
            
        

async def listen_to_conclave(app: FastAPI):
    global cpp_writer, rooms, pending_acks, SECRET_KEY
    while True:
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', 6666)
            cpp_writer = writer
            print("--- SUCCESS: Connected to Conclave Core ---")
            
            while True:
                header = await reader.readexactly(4)
                size = struct.unpack('!I', header)[0]
                payload = await reader.readexactly(size)

                msg_type = payload[0]
                
                if msg_type == 1: # CMD - Receive Secret Key
                    if len(payload) >= 33:
                        SECRET_KEY = payload[1:33]
                        print("[CRYPTO] Secret Key Synchronized.")
                
                elif msg_type == 2: # MessageType::ROOM_LIST
                    await update_room_data(payload[1:])
                
                elif msg_type == 3: # MessageType::ACK
                    # payload[1] is the AckType (Connect or Join)
                    ack_router(payload[1], payload[2:])
                else:
                    print(f"[WARN] Unknown msg type: {msg_type}")

        except asyncio.IncompleteReadError:
            print("[ERROR] C++ Core closed the connection.")
            cpp_writer = None
            await asyncio.sleep(2)
        except Exception as e:
            print(f"[ERROR] Bridge failure: {e}")
            cpp_writer = None
            await asyncio.sleep(2)

# --- HELPER FUNCTIONS ---

def format_conclave_msg(msg_type: int, payload: bytes) -> bytes:
    """[4-byte Length][1-byte Type][Payload]"""
    body = bytes([msg_type]) + payload
    return struct.pack('!I', len(body)) + body

async def update_room_data(data: bytes):
    global rooms
    new_rooms = {}
    offset = 0
    while offset < len(data):
        room_id = struct.unpack('!I', data[offset:offset+4])[0]
        offset += 4
        name_len = data[offset]
        offset += 1
        name = data[offset:offset+name_len].decode('utf-8')
        offset += name_len
        new_rooms[room_id] = name
    rooms = new_rooms
    print(f"[SYNC] Core updated: {len(rooms)} rooms active.")

# --- ENDPOINTS ---

@app.get("/")
async def root():
    return FileResponse("static/index.html")

@app.post("/room={roomId}")
async def room(roomId: int, uid: int = Form(...)): # Look for 'uid' in the POST body
    print(f"POST Join: Room {roomId}, UID {uid}")
    
    global cpp_writer, gen_acks
    ack_event = asyncio.Event()
    gen_acks[uid] = ack_event

    # Handshake with C++ Core (same as before)
    payload = struct.pack('!BII', 6, roomId, uid)
    msg = format_conclave_msg(1, payload)
    cpp_writer.write(msg)
    await cpp_writer.drain()
    
    try:
        await asyncio.wait_for(ack_event.wait(), timeout=2.0)
        gen_acks.pop(uid, None)
        # Serve the HTML file in response to the POST
        return FileResponse("static/room.html")
    except asyncio.TimeoutError:
        gen_acks.pop(uid, None)
        raise HTTPException(status_code=504, detail="C++ Core timeout.")


@app.get("/rooms")
async def get_rooms():
    return {"rooms": rooms}

@app.get("/get-token")
async def get_token(tab_id: str):
    token = await create_conclave_token(tab_id)
    if isinstance(token, dict):
        raise HTTPException(status_code=504, detail=token["message"])
    return token

@app.post("/create-room")
async def create_room(room_name: str, room_pw: str):
    if not cpp_writer:
        raise HTTPException(status_code=503, detail="C++ Backend Offline")
    create_opcode = b'\x02'
    msg_payload = f"{room_name.replace(' ', '-')}~{room_pw}".encode('utf-8')
    full_msg = format_conclave_msg(1, create_opcode + msg_payload)
    cpp_writer.write(full_msg)
    await cpp_writer.drain()
    return {"status": "request sent"}

@app.put("/join") # Removed {roomId} from path to match your index.html call
async def join_room(roomId: int, user_id: int, password: str):
    if not cpp_writer:
        raise HTTPException(status_code=503, detail="C++ Backend Offline")
    ack_event = asyncio.Event()
    pending_acks[user_id] = ack_event

    join_opcode = b'\x00' # Commands::JOIN
    binary_ids = struct.pack('!I', roomId) + struct.pack('!I', user_id)
    payload = join_opcode + binary_ids + password.encode('utf-8')
    
    full_msg = format_conclave_msg(1, payload) # MessageType::CMD

    try:
        cpp_writer.write(full_msg)
        await cpp_writer.drain()

        try:
            # Wait for C++ to verify and send the ACK
            await asyncio.wait_for(ack_event.wait(), timeout=2.0) 
            return {"status": "success", "message": "Access Granted"}
        except asyncio.TimeoutError:
            raise HTTPException(status_code=403, detail="Access Denied: Invalid credentials or timeout.")
    finally:
        pending_acks.pop(user_id, None)

@app.put("/leave")
async def leave_room(roomId: int, user_id: int):
    if not cpp_writer:
        raise HTTPException(status_code=503, detail="C++ Backend Offline")
    ack_event = asyncio.Event()
    pending_acks[user_id] = ack_event

    opcode = b'\x01' # Commands::LEAVE
    if roomId is None:
        binary_ids = struct.pack('!I', user_id)
    else:
        binary_ids = struct.pack('!I', roomId) + struct.pack('!I', user_id)
    payload = opcode + binary_ids
    
    full_msg = format_conclave_msg(1, payload) # MessageType::CMD

    try:
        cpp_writer.write(full_msg)
        await cpp_writer.drain()
    except:
        raise HTTPException(status_code=400, detail="Failed to contact main server")

@app.post("/delete-room")
async def delete_room(roomId: int, room_pw: str):
    if not cpp_writer:
        raise HTTPException(status_code=503, detail="C++ Backend Offline")
    destroy_opcode = b'\x03'
    payload = destroy_opcode + struct.pack('!I', roomId) + room_pw.encode('utf-8')
    full_msg = format_conclave_msg(1, payload)
    cpp_writer.write(full_msg)
    await cpp_writer.drain()
    return {"status": "request sent"}

async def create_conclave_token(tab_id: str):
    global cpp_writer, user_queue, tab2u, SECRET_KEY
    if SECRET_KEY is None:
        return {"status": "error", "message": "Crypto core not initialized"}
    print(f"[CONNECT] Tab ID: {tab_id}")
    ack_event = asyncio.Event()
    user_queue[tab_id] = ack_event

    data = struct.pack('!B', 5) + tab_id.encode('utf-8')
    msg = format_conclave_msg(1, data)
    try:
        cpp_writer.write(msg)
        await cpp_writer.drain()

        await asyncio.wait_for(ack_event.wait(), timeout=5.0)
        user_queue.pop(tab_id)
        uid = tab2u.pop(tab_id)
        message = struct.pack('!I', uid) + tab_id.encode('utf-8')

        # FIX: digestmod= is required in modern Python
        signature = hmac.new(SECRET_KEY, message, digestmod=hashlib.sha256).digest()
        token_data = message + signature
        return base64.b64encode(token_data).decode('utf-8')

    except asyncio.TimeoutError:
        user_queue.pop(tab_id, None)
        return {"status": "error", "message": "Core timeout during UID assignment"}

@app.get('/status')
async def connection_status():
    global cpp_writer
    if cpp_writer is None:
        raise HTTPException(status_code=425, detail="Connection is not established")
    return True

@app.post('/disconnect')
async def disconnect_user(uid: int):
    global cpp_writer
    if not cpp_writer:
        return

    print(f"[DISCONNECT] Disconnecting User: {uid}")
    
    payload = b'\x04' + struct.pack('!I', uid)
    msg = format_conclave_msg(1, payload)
    
    cpp_writer.write(msg)
    await cpp_writer.drain()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)