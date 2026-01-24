const net = require("net");

//Config
const PORT = process.env.PORT || 6510;
const MAGIC = "BRlCK";
const MAGIC_LEN = MAGIC.length;
const MAX_PACKET_SIZE = 1024;
const MAX_CLIENTS = 10;
const HEARTBEAT_TIMEOUT = 15000;
const HEARTBEAT_CHECK_INTERVAL = 5000;

//Packet types
const TYPE_CONFIRM_CONNECTED    = 0;
const TYPE_CLIENT_CONNECTED     = 1;
const TYPE_CLIENT_DISCONNECTED  = 2;
const TYPE_CLIENT_DATA          = 3;
const TYPE_SERVER_FULL          = 4;

/*Incoming data format:
    MAGIC (5 bytes, "BRlCK")
    LENGTH (uint16, expected length of payload)
    PAYLOAD (variable)
*/

/*Outgoing data format:
    MAGIC (5 bytes, "BRlCK")
    LENGTH (uint16, expected length of payload)
    TYPE (uint8, type of packet)
    CLIENT_ID (uint16, ID of client from which packet originates)
    PAYLOAD (variable, optional)
*/

let nextClientId = 1;
const clients = new Map(); // Socket -> {id, buffer}

const server = net.createServer(socket => {
    if (clients.size >= MAX_CLIENTS) {
        socket.write(buildServerPacket(TYPE_SERVER_FULL, 0));
        socket.end();
        return;
    }

    const clientId = nextClientId++;
    clients.set(socket, { id : clientId, buffer : Buffer.alloc(0), lastSeen : Date.now() });

    console.log(`Client ${clientId} connected`);

    socket.write(buildServerPacket(TYPE_CONFIRM_CONNECTED, clientId));
    broadcast(buildServerPacket(TYPE_CLIENT_CONNECTED, clientId));

    socket.on("data", chunk => {
        const client = clients.get(socket);
        if (client == null) return;

        client.buffer = Buffer.concat([client.buffer, chunk]);

        processIncomingPackets(socket, client);
    });

    socket.on("close", () => disconnectClient(socket));
    socket.on("error", err => {
        console.error(`Client socket error:`, err);
        disconnectClient(socket)
    });
});

server.listen(PORT, () => {
    console.log(`Relay server listening on port ${PORT}`);
});

setInterval(() => {
    const now = Date.now();
    for (const [socket, client] of clients.entries()) {
        if (now - client.lastSeen > HEARTBEAT_TIMEOUT) {
            console.log(`Client ${client.id} timed out`);
            disconnectClient(socket);
        }
    }
}, HEARTBEAT_CHECK_INTERVAL);

function processIncomingPackets(socket, client) {
    let buffer = client.buffer;

    while (true) {
        if (buffer.length < MAGIC_LEN + 2) break; //Check if buffer is long enough to include MAGIC and LENGTH

        if (buffer.slice(0, MAGIC_LEN).toString("utf8") !== MAGIC) { //Check MAGIC
            disconnectClient(socket);
            return;
        }

        const payloadLength = buffer.readUInt16BE(MAGIC_LEN);
        const totalLength = MAGIC_LEN + 2 + payloadLength;

        if (payloadLength > MAX_PACKET_SIZE) { //Check if packet is too large
            disconnectClient(socket);
            return;
        }

        client.lastSeen = Date.now();

        if (buffer.length < totalLength) break; //Packet isn't complete yet

        const payload = buffer.slice(MAGIC_LEN + 2, totalLength);

        if (payloadLength > 0) broadcast(buildServerPacket(TYPE_CLIENT_DATA, client.id, payload));

        buffer = buffer.slice(totalLength);
    }

    client.buffer = buffer;
}

function disconnectClient(socket) {
    const client = clients.get(socket);
    if (client == null) return;

    console.log(`Client ${client.id} disconnected`);

    broadcast(buildServerPacket(TYPE_CLIENT_DISCONNECTED, client.id));

    clients.delete(socket);
    socket.destroy();
}

function broadcast(buffer) {
    for (const socket of clients.keys()) {
        if (!socket.destroyed) {
            socket.write(buffer);
        }
    }
}

function buildServerPacket(type, clientId, payload = null) {
    const payloadLength = (payload == null) ? 0 : payload.length;
    const totalLength = MAGIC.length + 2 + 1 + 2 + 1 + payloadLength;

    const buffer = Buffer.alloc(totalLength);
    let offset = 0;

    buffer.write(MAGIC, offset);
    offset += MAGIC.length;
    buffer.writeUInt8(0, offset); //Null terminating character for MAGIC string
    offset += 1;
    buffer.writeUInt16LE(1 + 2 + payloadLength, offset);
    offset += 2;
    buffer.writeUInt8(type, offset);
    offset += 1;
    buffer.writeUInt16LE(clientId, offset);
    offset += 2;

    if (payload != null) {
        payload.copy(buffer, offset);
    }

    return buffer;
}

function shutdown() {
    console.log("Server shutting down...");
    for (const socket of clients.keys()) {
        disconnectClient(socket);
    }
    server.close(() => {
        console.log("Server closed.");
        process.exit(0);
    });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
process.on("uncaughtException", (err) => {
    console.error("Uncaught exception:", err);
    shutdown();
});