from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from contextlib import asynccontextmanager
import struct
import asyncio
import uvicorn

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("FastAPI Lifespan Starting...")
    app.state.conclave_task = asyncio.create_task(listen_to_conclave(app))

    yield

    print("FastAPI Lifespan Shutting Down...")
    app.state.conclave_task.cancel()
    # FIX: await the task after cancelling so teardown completes before process exits
    try:
        await app.state.conclave_task
    except asyncio.CancelledError:
        pass

    if cpp_writer:
        cpp_writer.close()
        await cpp_writer.wait_closed()

app = FastAPI(title="Conclave", lifespan=lifespan)

rooms: dict[int, str] = {}
cpp_writer: asyncio.StreamWriter | None = None

async def listen_to_conclave(app: FastAPI):
    global cpp_writer, rooms
    while True:
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', 6666)
            cpp_writer = writer
            
            while True:
                header = await reader.readexactly(4)
                size = struct.unpack('!I', header)[0]
                payload = await reader.readexactly(size)

                # MessageType::ROOM_LIST is index 2 in your C++ enum
                if payload[0] == 2: 
                    await update_room_data(payload[1:])
                else:
                    print(f"Received unknown msg type: {payload[0]}")

        except Exception as e:
            cpp_writer = None
            await asyncio.sleep(2)

@app.get("/")
async def root():
    return RedirectResponse(url="/docs")

async def update_room_data(data: bytes):
    global rooms
    new_rooms: dict[int, str] = {}
    offset = 0

    while offset < len(data):
        if offset + 4 > len(data):
            print("[WARN] Truncated room_id in ROOM_LIST packet — skipping remainder")
            break
        room_id = struct.unpack('!I', data[offset:offset + 4])[0]
        offset += 4

        if offset + 1 > len(data):
            print("[WARN] Truncated name_len in ROOM_LIST packet — skipping remainder")
            break
        name_len = data[offset]
        offset += 1

        if offset + name_len > len(data):
            print("[WARN] Truncated name in ROOM_LIST packet — skipping remainder")
            break
        name = data[offset:offset + name_len].decode('utf-8')
        offset += name_len

        new_rooms[room_id] = name

    rooms = new_rooms
    print(f"Synced {len(rooms)} rooms from Conclave core.")

@app.put("/{room_name}")
async def join_room(room_name: str):
    # TODO: implement join logic — send JOIN command to C++ core
    return {"status": "not implemented"}, 501

@app.post("/create-room")
async def create_room(room_name: str, room_pw: str):
    global cpp_writer

    if cpp_writer is None:
        return {"status": "error", "message": "Backend offline."}

    # Protocol: [4-byte Size][1-byte MessageType::CMD][1-byte Commands::CREATE][name~password]
    CREATE_OPCODE = b'\x02'
    msg_payload = f"{room_name.replace(' ', '-')}~{room_pw}".encode('utf-8')

    # MessageType::CMD == 1
    full_msg = format_conclave_msg(1, CREATE_OPCODE + msg_payload)

    try:
        cpp_writer.write(full_msg)
        await cpp_writer.drain()
    except (BrokenPipeError, ConnectionResetError) as e:
        cpp_writer = None
        return {"status": "error", "message": f"Lost connection to backend: {e}"}

    return {"status": "request sent"}

@app.get("/rooms")
async def get_rooms():
    return {"rooms": rooms}


def format_conclave_msg(msg_type: int, payload: bytes) -> bytes:
    """
    Frame a message for the Conclave wire protocol:
        [4-byte big-endian length of (type_byte + payload)] [type_byte] [payload]

    FIX: previously did `len(payload) + 1` for the size then prepended BOTH
    the type byte AND the payload, so the C++ reader would consume one byte
    short on every packet, corrupting the stream. The size field must equal
    exactly the number of bytes that follow it.
    """
    body = bytes([msg_type]) + payload
    return struct.pack('!I', len(body)) + body

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="debug")