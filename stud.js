const net = require("net");

//Config
const PORT = process.env.PORT || 6510;
const MAGIC = "BRlCK";
const MAGIC_LEN = MAGIC.length;
const MAX_PACKET_SIZE = 1024;
const MAX_UNAUTH_BUFFER = 2048;
const MAX_CLIENTS = 10;
const HEARTBEAT_TIMEOUT = 15000;
const HEARTBEAT_CHECK_INTERVAL = 5000;
let hostSocket = null;
let nextClientId = 2;
const clients = new Map(); // Socket -> {id, buffer}

//Packet types
const TYPE_CONFIRM_CONNECTED    = 1;
const TYPE_CLIENT_DISCONNECTED  = 2;
const TYPE_CLIENT_DATA          = 3;
const TYPE_SERVER_FULL          = 4;

/*Incoming data format:
    MAGIC (5 bytes, "BRlCK")
    LENGTH (uint16, expected length of payload)
    ADDRESSEE (uint16, client to forward packet to { 0 : all, 1 : host})
    PAYLOAD (variable)
*/

/*Outgoing data format:
    MAGIC (6 bytes, "BRlCK" plus null terminating character)
    LENGTH (uint16, expected length of payload)
    TYPE (uint8, type of packet)
    CLIENT_ID (uint16, ID of client from which packet originates)
    PAYLOAD (variable, optional)
*/

const server = net.createServer(socket => {
    if (authenticatedClientCount() >= MAX_CLIENTS) {
        socket.write(buildServerPacket(TYPE_SERVER_FULL, 0));
        socket.end();
        return;
    }

    clients.set(socket, { id : null, buffer : Buffer.alloc(0), lastSeen : Date.now(), auth : false });

    socket.on("data", chunk => {
        const client = clients.get(socket);
        if (client == null) return;

        if (!client.auth && client.buffer.length + chunk.length > MAX_UNAUTH_BUFFER) {
            console.log(`Unauthenticated client sent too much data, disconnecting`);
            clients.delete(socket);
            socket.destroy();
            return;
        }

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
            console.log(client.auth ? `Client ${client.id} timed out` : `Unauthenticated socket timed out`);
            disconnectClient(socket);
        }
    }
}, HEARTBEAT_CHECK_INTERVAL);

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
process.on("uncaughtException", (err) => {
    console.error("Uncaught exception:", err);
    shutdown();
});

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~HELPERS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

function processIncomingPackets(socket, client) {
    let buffer = client.buffer;

    while (true) {
        if (buffer.length < MAGIC_LEN + 2 + 2) break; //Check if buffer is long enough to include MAGIC and LENGTH and ADDRESSEE
        
        const receivedMagic = buffer.slice(0, MAGIC_LEN).toString("utf8");
        const payloadLength = buffer.readUInt16LE(MAGIC_LEN);
        const addressee = buffer.readUInt16LE(MAGIC_LEN + 2);
        const totalLength = MAGIC_LEN + 2 + 2 + payloadLength;

        if (receivedMagic !== MAGIC) { //Check MAGIC
            if (!client.auth) {
                clients.delete(socket);
                socket.destroy();
            } else {
                console.log(`MAGIC invalid: ${receivedMagic}`);
                disconnectClient(socket);
            }
            return;
        }

        if (payloadLength > MAX_PACKET_SIZE) { //Check if packet is too large
            if (!client.auth) {
                clients.delete(socket);
                socket.destroy();
            } else {
                console.log(`Packet too large: ${payloadLength}`);
                disconnectClient(socket);
            }
            return;
        }

        //If packet has reached this point, it's valid
        if (!client.auth) {
            client.id = nextClientId++;
            client.auth = true;

            if (hostSocket === null) {
                hostSocket = socket;
                console.log(`Client ${client.id} is HOST`);
                socket.write(buildServerPacket(TYPE_CONFIRM_CONNECTED, client.id, Buffer.from([1])));
            }
            else socket.write(buildServerPacket(TYPE_CONFIRM_CONNECTED, client.id, Buffer.from([0])));

            console.log(`Client ${client.id} connected and authenticated`);
        }

        if (buffer.length < totalLength) break; //Packet isn't complete yet

        const payload = buffer.slice(MAGIC_LEN + 2 + 2, totalLength);

        if (payloadLength > 0) forwardPacket(buildServerPacket(TYPE_CLIENT_DATA, client.id, payload), addressee);

        buffer = buffer.slice(totalLength + 1);

        client.lastSeen = Date.now();
    }

    client.buffer = buffer;
}

function disconnectClient(socket) {
    const client = clients.get(socket);
    if (client == null) return;

    if (client.auth) {
        console.log(`Client ${client.id} disconnected`);
        forwardPacket(buildServerPacket(TYPE_CLIENT_DISCONNECTED, client.id), 0);
    }

    clients.delete(socket);

    //Assign new host if disconnected
    if (socket === hostSocket) {
        hostSocket = null;

        let newHost = null;
        for (const [socket, client] of clients.entries()) {
            if (client.auth && (newHost === null || client.id < newHost.client.id)) {
                newHost = {socket, client};
            }
        }

        if (newHost != null) {
            hostSocket = newHost.socket;
            console.log(`Client ${newHost.client.id} promoted to HOST`);
            hostSocket.write(buildServerPacket(TYPE_CONFIRM_CONNECTED, newHost.client.id, Buffer.from([1])));
        }
    }

    socket.destroy();
}

function forwardPacket(buffer, addressee) {
    if (addressee === 0) {
        for (const [socket, client] of clients.entries()) {
            if (client.auth && !socket.destroyed) {
                socket.write(buffer);
            }
        }
        return;
    }

    if (addressee === 1) {
        if (hostSocket != null && !hostSocket.destroyed) {
            hostSocket.write(buffer);
        }
        return;
    }

    for (const [socket, client] of clients.entries()) {
        if (client.auth && client.id === addressee) {
            socket.write(buffer);
            return;
        }
    }

    console.log(`Packet dropped, addressed to ${addressee}`);
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
    buffer.writeUInt16LE(payloadLength, offset);
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

function authenticatedClientCount() {
    let count = 0;
    for (const client of clients.values()) {
        if (client.auth) count++;
    }
    return count;
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