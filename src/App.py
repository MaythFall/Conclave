import asyncio
import struct
import random
from fastapi import FastAPI, HTTPException
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

def ack_router(mtype: int, data):
    if mtype == 0: #Connect
        uid = struct.unpack('!I', data[1:5])[0]
        ack_id = data[5:].decode('utf-8')
        if ack_id in user_queue:
            print(f"[ACK] Received UID for TAB: {ack_id}")
            tab2u[ack_id] = uid
            user_queue[ack_id].set()
    elif mtype == 1: # Join
        ack_id = struct.unpack('!I', data[1:5])[0]
        if ack_id in pending_acks:
            print(f"[ACK] Received confirmation for UID: {ack_id}")
            pending_acks[ack_id].set()

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
                
                if msg_type == 1: #CMD - Only Received CMD is Secret Key
                    if len(payload) >= 33:
                        SECRET_KEY = payload[1:33]
                elif msg_type == 2: # MessageType::ROOM_LIST
                    await update_room_data(payload[1:])
                
                elif msg_type == 3: # MessageType::ACK
                    if len(payload) >= 5:
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

@app.get("/rooms")
async def get_rooms():
    return {"rooms": rooms}

@app.post("/create-room")
async def create_room(room_name: str, room_pw: str):
    if not cpp_writer:
        raise HTTPException(status_code=503, detail="C++ Backend Offline")

    # Commands::CREATE == 2
    create_opcode = b'\x02'
    msg_payload = f"{room_name.replace(' ', '-')}~{room_pw}".encode('utf-8')
    
    # MessageType::CMD == 1
    full_msg = format_conclave_msg(1, create_opcode + msg_payload)
    cpp_writer.write(full_msg)
    await cpp_writer.drain()
    return {"status": "request sent"}

@app.put("/join")
async def join_room(roomId: int, user_id: int, password: str):
    if not cpp_writer:
        raise HTTPException(status_code=503, detail="C++ Backend Offline")

    # Create an event to wait for the specific ACK from C++
    ack_event = asyncio.Event()
    pending_acks[user_id] = ack_event

    # Commands::JOIN == 0
    join_opcode = b'\x00'
    binary_ids = struct.pack('!II', roomId, user_id)
    payload = join_opcode + binary_ids + password.encode('utf-8')
    
    full_msg = format_conclave_msg(1, payload)
    
    

    try:
        cpp_writer.write(full_msg)
        await cpp_writer.drain()

        # Wait up to 2.0 seconds for C++ to verify password and send ACK
        try:
            await asyncio.wait_for(ack_event.wait(), timeout=2.0)
            return FileResponse("static/room.html")
        except asyncio.TimeoutError:
            return {"status": "error", "message": "Access Denied: Invalid credentials or timeout."}
    finally:
        # Clean up the event tracker
        pending_acks.pop(user_id, None)

@app.post("{roomId}/leave")
async def leave_room(roomId: int, uid: int):
    if not cpp_writer:
        raise HTTPException(status_code=503, detail="C++ Backend Offline")
    leave_code = b'/x01'
    b_id = struct.pack('!I', uid)
    payload = leave_code + b_id
    msg = format_conclave_msg(1, payload)
    cpp_writer.write(msg)
    return FileResponse("static/index.html")

@app.post("/delete-room")
async def delete_room(roomId: int, room_pw: str):
    if not cpp_writer:
        raise HTTPException(status_code=503, detail="C++ Backend Offline")

    # Commands::DESTROY == 3
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

    ack_event = asyncio.Event()
    user_queue[tab_id] = ack_event
    
    msg = format_conclave_msg(5, tab_id.encode('utf-8')) 
    try:
        cpp_writer.write(msg)
        await cpp_writer.drain()
        
        await asyncio.wait_for(ack_event.wait(), timeout=2.0)
        
        uid = tab2u.pop(tab_id)
        message = f"{uid}:{tab_id}".encode('utf-8')
        
        signature = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()
        token_data = message + b"." + signature
        return base64.b64encode(token_data).decode('utf-8')
        
    except asyncio.TimeoutError:
        user_queue.pop(tab_id, None)
        return {"status": "error", "message": "Core timeout during UID assignment"}



if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)