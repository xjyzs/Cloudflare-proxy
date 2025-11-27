// 如需要使用环境变量,将462至468行取消注释
import { connect } from 'cloudflare:sockets';

let subPath = 'link';     // 节点订阅路径,不修改将使用UUID作为订阅路径
let proxyIP = '210.61.97.241:81';  // proxyIP 格式：ip、域名、ip:port、域名:port等,没填写port，默认使用443
let password = '5dc15e15-f285-4a9d-959b-0e4fbdd77b63';  // 节点UUID
let SSpath = '';          // 路径验证，为空则使用UUID作为验证路径
const nginxHtml = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
    width: 35em;
    margin: 0 auto;
    font-family: Tahoma, Verdana, Arial, sans-serif;
}
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
    working. Further configuration is required.</p>

<p>For online documentation and support please refer to
    <a href="http://nginx.org/">nginx.org</a>.<br/>
    Commercial support is available at
    <a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`
const head=`port: 7890
socks-port: 7891
allow-lan: true
mode: Rule
dns:
  enable: true
proxies:
`
const mid=`
proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
`

// CF-CDN
let cfip = [ // 格式:优选域名:端口#备注名称、优选IP:端口#备注名称、[ipv6优选]:端口#备注名称、优选域名#备注
    'mfa.gov.ua#SG', 'saas.sin.fan#JP', 'store.ubi.com#SG','cf.130519.xyz#KR','cf.008500.xyz#HK',
    'cf.090227.xyz#SG', 'cf.877774.xyz#HK','cdns.doon.eu.org#JP','sub.danfeng.eu.org#TW','cf.zhetengsha.eu.org#HK'
];  // 感谢各位大佬维护的优选域名

function closeSocketQuietly(socket) {
    try {
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close();
        }
    } catch (error) {}
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try {
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

function parsePryAddress(serverStr) {
    if (!serverStr) return null;
    serverStr = serverStr.trim();
    if (serverStr.startsWith('socks://') || serverStr.startsWith('socks5://')) {
        const urlStr = serverStr.replace(/^socks:\/\//, 'socks5://');
        try {
            const url = new URL(urlStr);
            return {
                type: 'socks5',
                host: url.hostname,
                port: parseInt(url.port) || 1080,
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    if (serverStr.startsWith('http://') || serverStr.startsWith('https://')) {
        try {
            const url = new URL(serverStr);
            return {
                type: 'http',
                host: url.hostname,
                port: parseInt(url.port) || (serverStr.startsWith('https://') ? 443 : 80),
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    if (serverStr.startsWith('[')) {
        const closeBracket = serverStr.indexOf(']');
        if (closeBracket > 0) {
            const host = serverStr.substring(1, closeBracket);
            const rest = serverStr.substring(closeBracket + 1);
            if (rest.startsWith(':')) {
                const port = parseInt(rest.substring(1), 10);
                if (!isNaN(port) && port > 0 && port <= 65535) {
                    return { type: 'direct', host, port };
                }
            }
            return { type: 'direct', host, port: 443 };
        }
    }
    const lastColonIndex = serverStr.lastIndexOf(':');
    if (lastColonIndex > 0) {
        const host = serverStr.substring(0, lastColonIndex);
        const portStr = serverStr.substring(lastColonIndex + 1);
        const port = parseInt(portStr, 10);
        if (!isNaN(port) && port > 0 && port <= 65535) {
            return { type: 'direct', host, port };
        }
    }
    return { type: 'direct', host: serverStr, port: 443 };
}

function isSpeedTestSite(hostname) {
    const speedTestDomains = ['speedtest.net','fast.com','speedtest.cn','speed.cloudflare.com', 'ovo.speedtestcustom.com'];
    if (speedTestDomains.includes(hostname)) {
        return true;
    }
    for (const domain of speedTestDomains) {
        if (hostname.endsWith('.' + domain) || hostname === domain) {
            return true;
        }
    }
    return false;
}

async function handleSSRequest(request, customProxyIP) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);
    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            const { hasError, message, addressType, port, hostname, rawIndex } = parseSSPacketHeader(chunk);
            if (hasError) throw new Error(message);

            if (isSpeedTestSite(hostname)) {
                throw new Error('Speedtest site is blocked');
            }
            if (addressType === 2) {
                if (port === 53) isDnsQuery = true;
                else throw new Error('UDP is not supported');
            }
            const rawData = chunk.slice(rawIndex);
            if (isDnsQuery) return forwardataudp(rawData, serverSock, null);
            await forwardataTCP(hostname, port, rawData, serverSock, null, remoteConnWrapper, customProxyIP);
        },
    })).catch((err) => {
        // console.error('Readable pipe error:', err);
    });
    return new Response(null, { status: 101, webSocket: clientSock });
}

function parseSSPacketHeader(chunk) {
    if (chunk.byteLength < 7) return { hasError: true, message: 'Invalid data' };
    try {
        const view = new Uint8Array(chunk);
        const addressType = view[0];
        let addrIdx = 1, addrLen = 0, addrValIdx = addrIdx, hostname = '';
        switch (addressType) {
            case 1: // IPv4
                addrLen = 4;
                hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.');
                addrValIdx += addrLen;
                break;
            case 3: // Domain
                addrLen = view[addrIdx];
                addrValIdx += 1;
                hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen));
                addrValIdx += addrLen;
                break;
            case 4: // IPv6
                addrLen = 16;
                const ipv6 = [];
                const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen));
                for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
                hostname = ipv6.join(':');
                addrValIdx += addrLen;
                break;
            default:
                return { hasError: true, message: `Invalid address type: ${addressType}` };
        }
        if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
        const port = new DataView(chunk.slice(addrValIdx, addrValIdx + 2)).getUint16(0);
        return { hasError: false, addressType, port, hostname, rawIndex: addrValIdx + 2 };
    } catch (e) {
        return { hasError: true, message: 'Failed to parse SS packet header' };
    }
}

async function connect2Socks5(proxyConfig, targetHost, targetPort, initialData) {
    const { host, port, username, password } = proxyConfig;
    const socket = connect({ hostname: host, port: port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    try {
        const authMethods = username && password ?
            new Uint8Array([0x05, 0x02, 0x00, 0x02]) :
            new Uint8Array([0x05, 0x01, 0x00]);

        await writer.write(authMethods);
        const methodResponse = await reader.read();
        if (methodResponse.done || methodResponse.value.byteLength < 2) {
            throw new Error('S5 method selection failed');
        }
        const selectedMethod = new Uint8Array(methodResponse.value)[1];
        if (selectedMethod === 0x02) {
            if (!username || !password) {
                throw new Error('S5 requires authentication');
            }
            const userBytes = new TextEncoder().encode(username);
            const passBytes = new TextEncoder().encode(password);
            const authPacket = new Uint8Array(3 + userBytes.length + passBytes.length);
            authPacket[0] = 0x01;
            authPacket[1] = userBytes.length;
            authPacket.set(userBytes, 2);
            authPacket[2 + userBytes.length] = passBytes.length;
            authPacket.set(passBytes, 3 + userBytes.length);
            await writer.write(authPacket);
            const authResponse = await reader.read();
            if (authResponse.done || new Uint8Array(authResponse.value)[1] !== 0x00) {
                throw new Error('S5 authentication failed');
            }
        } else if (selectedMethod !== 0x00) {
            throw new Error(`S5 unsupported auth method: ${selectedMethod}`);
        }
        const hostBytes = new TextEncoder().encode(targetHost);
        const connectPacket = new Uint8Array(7 + hostBytes.length);
        connectPacket[0] = 0x05;
        connectPacket[1] = 0x01;
        connectPacket[2] = 0x00;
        connectPacket[3] = 0x03;
        connectPacket[4] = hostBytes.length;
        connectPacket.set(hostBytes, 5);
        new DataView(connectPacket.buffer).setUint16(5 + hostBytes.length, targetPort, false);
        await writer.write(connectPacket);
        const connectResponse = await reader.read();
        if (connectResponse.done || new Uint8Array(connectResponse.value)[1] !== 0x00) {
            throw new Error('S5 connection failed');
        }
        await writer.write(initialData);
        writer.releaseLock();
        reader.releaseLock();
        return socket;
    } catch (error) {
        writer.releaseLock();
        reader.releaseLock();
        throw error;
    }
}

async function connect2Http(proxyConfig, targetHost, targetPort, initialData) {
    const { host, port, username, password } = proxyConfig;
    const socket = connect({ hostname: host, port: port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    try {
        let connectRequest = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
        connectRequest += `Host: ${targetHost}:${targetPort}\r\n`;

        if (username && password) {
            const auth = btoa(`${username}:${password}`);
            connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
        }
        connectRequest += `User-Agent: Mozilla/5.0\r\n`;
        connectRequest += `Connection: keep-alive\r\n`;
        connectRequest += '\r\n';
        await writer.write(new TextEncoder().encode(connectRequest));
        let responseBuffer = new Uint8Array(0);
        let headerEndIndex = -1;
        let bytesRead = 0;
        const maxHeaderSize = 8192;
        while (headerEndIndex === -1 && bytesRead < maxHeaderSize) {
            const { done, value } = await reader.read();
            if (done) {
                throw new Error('Connection closed before receiving HTTP response');
            }
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;
            bytesRead = responseBuffer.length;

            for (let i = 0; i < responseBuffer.length - 3; i++) {
                if (responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a &&
                    responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a) {
                    headerEndIndex = i + 4;
                    break;
                }
            }
        }
        if (headerEndIndex === -1) {
            throw new Error('Invalid HTTP response');
        }
        const headerText = new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex));
        const statusLine = headerText.split('\r\n')[0];
        const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
        if (!statusMatch) {
            throw new Error(`Invalid response: ${statusLine}`);
        }
        const statusCode = parseInt(statusMatch[1]);
        if (statusCode < 200 || statusCode >= 300) {
            throw new Error(`Connection failed: ${statusLine}`);
        }
        await writer.write(initialData);
        writer.releaseLock();
        reader.releaseLock();
        return socket;
    } catch (error) {
        try {
            writer.releaseLock();
        } catch (e) {}
        try {
            reader.releaseLock();
        } catch (e) {}
        try {
            socket.close();
        } catch (e) {}
        throw error;
    }
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, customProxyIP) {
    async function connectDirect(address, port, data) {
        const remoteSock = connect({ hostname: address, port: port });
        const writer = remoteSock.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
        return remoteSock;
    }
    let proxyConfig = null;
    let shouldUseProxy = false;
    if (customProxyIP) {
        proxyConfig = parsePryAddress(customProxyIP);
        if (proxyConfig && (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https')) {
            shouldUseProxy = true;
        } else if (!proxyConfig) {
            proxyConfig = parsePryAddress(proxyIP) || { type: 'direct', host: proxyIP, port: 443 };
        }
    } else {
        proxyConfig = parsePryAddress(proxyIP) || { type: 'direct', host: proxyIP, port: 443 };
        if (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            shouldUseProxy = true;
        }
    }
    async function connecttoPry() {
        let newSocket;
        if (proxyConfig.type === 'socks5') {
            newSocket = await connect2Socks5(proxyConfig, host, portNum, rawData);
        } else if (proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            newSocket = await connect2Http(proxyConfig, host, portNum, rawData);
        } else {
            newSocket = await connectDirect(proxyConfig.host, proxyConfig.port, rawData);
        }
        remoteConnWrapper.socket = newSocket;
        newSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
        connectStreams(newSocket, ws, respHeader, null);
    }
    if (shouldUseProxy) {
        try {
            await connecttoPry();
        } catch (err) {
            throw err;
        }
    } else {
        try {
            const initialSocket = await connectDirect(host, portNum, rawData);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, connecttoPry);
        } catch (err) {
            await connecttoPry();
        }
    }
}

function makeReadableStr(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', (event) => {
                if (!cancelled) controller.enqueue(event.data);
            });
            socket.addEventListener('close', () => {
                if (!cancelled) {
                    closeSocketQuietly(socket);
                    controller.close();
                }
            });
            socket.addEventListener('error', (err) => controller.error(err));
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() {
            cancelled = true;
            closeSocketQuietly(socket);
        }
    });
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
    let header = headerData, hasData = false;
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                hasData = true;
                if (webSocket.readyState !== WebSocket.OPEN) controller.error('wsreadyState not open');
                if (header) {
                    const response = new Uint8Array(header.length + chunk.byteLength);
                    response.set(header, 0);
                    response.set(chunk, header.length);
                    webSocket.send(response.buffer);
                    header = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            abort() {},
        })
    ).catch((err) => {
        closeSocketQuietly(webSocket);
    });
    if (!hasData && retryFunc) {
        await retryFunc();
    }
}

async function forwardataudp(udpChunk, webSocket, respHeader) {
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let vlessHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WebSocket.OPEN) {
                    if (vlessHeader) {
                        const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
                        response.set(vlessHeader, 0);
                        response.set(chunk, vlessHeader.length);
                        webSocket.send(response.buffer);
                        vlessHeader = null;
                    } else {
                        webSocket.send(chunk);
                    }
                }
            },
        }));
    } catch (error) {
        // console.error('UDP forward error:', error);
    }
}

function getSimplePage(request) {
    const url = request.headers.get('Host');
    const baseUrl = `https://${url}`;
    return new Response(nginxHtml, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
    });
}

export default {
    async fetch(request,env) {
        try {
            // if (env.PROXYIP || env.proxyip || env.proxyIP) {
            //     const servers = (env.PROXYIP || env.proxyip || env.proxyIP).split(',').map(s => s.trim());
            //     //proxyIP = servers[0];
            // }
            // password = env.PASSWORD || env.password || env.uuid || env.UUID || password;
            // subPath = env.SUB_PATH || env.subpath || subPath;
            // SSpath = env.SSPATH || env.sspath || SSpath;
            if (subPath === 'link' || subPath === '') { subPath = password; }
            if (SSpath === '') { SSpath = password; }
            let validPath = `/${SSpath}`;
            const servers = proxyIP.split(',').map(s => s.trim());
            proxyIP = servers[0];
            const method = 'none';
            const url = new URL(request.url);
            const pathname = url.pathname;
            let pathProxyIP = null;
            if (pathname.startsWith('/proxyip=')) {
                try {
                    pathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
                } catch (e) {
                    // ingore error
                }
                if (pathProxyIP && !request.headers.get('Upgrade')) {
                    proxyIP = pathProxyIP;
                    return new Response(`set proxyIP to: ${proxyIP}\n\n`, {
                        headers: {
                            'Content-Type': 'text/plain; charset=utf-8',
                            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                        },
                    });
                }
            }

            if (request.headers.get('Upgrade') === 'websocket') {
                if (!pathname.toLowerCase().startsWith(validPath.toLowerCase())) {
                    return new Response('Unauthorized', { status: 401 });
                }
                let wsPathProxyIP = null;
                if (pathname.startsWith('/proxyip=')) {
                    try {
                        wsPathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
                    } catch (e) {
                        // ingore error
                    }
                }
                const customProxyIP = wsPathProxyIP || url.searchParams.get('proxyip') || request.headers.get('proxyip');
                return await handleSSRequest(request, customProxyIP);
            } else if (request.method === 'GET') {
                if (url.pathname === '/') {
                    return getSimplePage(request);
                }
                if (url.pathname.toLowerCase() === `/${password.toLowerCase()}`) {
                    const sheader = 's' + 's';
                    const typelink = 'c'+ 'l'+ 'a'+ 's'+ 'h';
                    const currentDomain = url.hostname;
                    const baseUrl = `https://${currentDomain}`;
                    const vUrl = `${baseUrl}/sub/${subPath}`;
                    const qxConfig = `shadowsocks=mfa.gov.ua:443,method=none,password=${password},obfs=wss,obfs-host=${currentDomain},obfs-uri=/${SSpath}/?ed=2560,fast-open=true, udp-relay=true,tag=SS`;
                    const claLink = `https://sub.ssss.xx.kg/${typelink}?config=${vUrl}`;
                    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Shadowsocks 订阅中心</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;padding:20px;background:linear-gradient(135deg,#7dd3ca 0%,#a17ec4 100%);color:#333}.container{height:1080px;max-width:800px;margin:0 auto}.header{margin-bottom:30px}.header h1{text-align:center;color:#007fff;border-bottom:2px solid #3498db;padding-bottom:10px}.section{margin-bottom:0px}.section h2{color:#b33ce7;margin-bottom:5px;font-size:1.1em}.link-box{background:#f0fffa;border:1px solid #ddd;border-radius:8px;padding:15px;margin-bottom:15px;display:flex;justify-content:space-between;align-items:flex-start}.lintext{flex:1;word-break:break-all;font-family:monospace;color:#2980b9;margin:10px;}.clesh-config{flex:1;word-break:break-all;font-family:monospace;color:#2980b9;margin:10px;white-space:pre-wrap;background:#f8f9fa;padding:10px;border-radius:4px;border:1px solid #e9ecef}.button-group{display:flex;gap:10px;flex-shrink:0}.copy-btn{background:#27aea2;color:white;border:none;padding:8px 15px;border-radius:4px;cursor:pointer;transition:all 0.3s ease}.copy-btn:hover{background:#219652}.copy-btn.copied{background:#0e981d}.qrcode-btn{background:#e67e22;color:white;border:none;padding:8px 15px;border-radius:4px;cursor:pointer}.qrcode-btn:hover{background:#d35400}.footer{text-align:center;color:#7f8c8d;border-top:1px solid #e1d9fb;}.footer a{color:#c311ffs;text-decoration:none;margin:0 15px}.footer a:hover{text-decoration:underline}#qrModal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:1000}.modal-content{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:white;padding:20px;border-radius:8px;text-align:center;max-width:90%}.modal-content h3{margin-bottom:15px;color:#2c3e50}.modal-content img{max-width:300px;height:auto;margin:10px 0}.close-btn{background:#e74c3c;color:white;border:none;padding:8px 15px;border-radius:4px;cursor:pointer;margin-top:15px}.close-btn:hover{background:#c0392b}@media (max-width:600px){.link-box{flex-direction:column}.button-group{margin-top:10px;align-self:flex-end}}</style></head><body><div class="container"><div class="header"><h1>Shadowsocks 订阅中心</h1></div><div class="section"><h2>V2rayN(7.16.4)/Nekobox/小火箭/v2rayng(安卓1.8.25)/kraing(1.2.8.1100以上) 订阅链接</h2><div class="link-box"><div class="lintext">${vUrl}</div><div class="button-group"><button class="copy-btn" onclick="copyToClipboard(this,'${vUrl}')">复制</button><button class="qrcode-btn" onclick="showQRCode('${vUrl}','V2rayN(7.16.4)/nekobox/小火箭/V2rayng(安卓1.8.25) 订阅链接')">二维码</button></div></div></div><div class="section"><h2>${typelink}订阅链接</h2><div class="link-box"><div class="lintext">${claLink}</div><div class="button-group"><button class="copy-btn" onclick="copyToClipboard(this,'${claLink}')">复制</button><button class="qrcode-btn" onclick="showQRCode('${claLink}','${typelink} 订阅链接')">二维码</button></div></div></div><div class="section"><h2>Quantumult X节点配置</h2><div class="link-box"><div class="lintext">${qxConfig}</div><div class="button-group"><button class="copy-btn" onclick="copyToClipboard(this,'${qxConfig}')">复制</button></div></div></div><div class="section"><h2>客户端下载链接</h2><div class="link-box"><div class="lintext">v2rayN (Windows): <a href="https://github.com/2dust/v2rayN/releases/tag/7.16.4" target="_blank">7.16.4版本下载</a><br>v2rayNG (Android): <a href="https://github.com/2dust/v2rayNG/releases/tag/1.8.25" target="_blank">1.8.25版本下载</a><br>Karing (测试版): <a href="https://github.com/KaringX/karing/releases/tag/v1.2.8.1101" target="_blank">1.2.8.1101版本下载</a></div></div></div><div class="footer"><p><a href="https://github.com/eooce/CF-workers-and-snip-VLESS" target="_blank">GitHub</a> | <a href="https://check-proxyip.ssss.nyc.mn" target="_blank">Proxyip检测</a> | <a href="https://t.me/+vtZ8GLzjksA4OTVl" target="_blank">TG交流群</a></p></div></div><div id="qrModal"><div class="modal-content"><h3 id="modalTitle">二维码</h3><img id="qrImage" src="" alt="QR Code"><p id="qrText" style="word-break:break-all;margin:10px 0"></p><button class="close-btn" onclick="closeQRModal()">关闭</button></div></div><script>function copyToClipboard(button,text){const originalText=button.textContent;const decodedText=text.replace(/\\\\n/g,'\\n').replace(/&quot;/g,'"');navigator.clipboard.writeText(decodedText).then(()=>{button.textContent='已复制';button.classList.add('copied');setTimeout(()=>{button.textContent=originalText;button.classList.remove('copied')},2000)}).catch(()=>{const e=document.createElement('textarea');e.value=decodedText;document.body.appendChild(e);e.select();document.execCommand('copy');document.body.removeChild(e);button.textContent='已复制';button.classList.add('copied');setTimeout(()=>{button.textContent=originalText;button.classList.remove('copied')},2000)})}function showQRCode(text,title){document.getElementById('modalTitle').textContent=title;document.getElementById('qrText').textContent=text;const e='https://tool.oschina.net/action/qrcode/generate?data='+encodeURIComponent(text)+'&output=image%2Fpng&error=L&type=0&margin=4&size=4';fetch(e).then(t=>t.blob()).then(t=>{const n=URL.createObjectURL(t);document.getElementById('qrImage').src=n}).catch(()=>{document.getElementById('qrImage').src=e});document.getElementById('qrModal').style.display='block'}function closeQRModal(){document.getElementById('qrModal').style.display='none'}document.addEventListener('DOMContentLoaded',function(){document.querySelectorAll('.copy-btn[data-config]').forEach(btn=>{btn.addEventListener('click',function(){copyToClipboard(this,this.getAttribute('data-config'))})})});</script></body></html>`;
                    return new Response(html, {
                        status: 200,
                        headers: {
                            'Content-Type': 'text/html;charset=utf-8',
                            'Cache-Control': 'no-cache, no-store, must-revalidate',
                        },
                    });
                }
                let nodeNames=[];
                // sub path /sub/UUID
                if (url.pathname.toLowerCase() === `/sub/${subPath.toLowerCase()}` || url.pathname.toLowerCase() === `/sub/${subPath.toLowerCase()}/`) {
                    const currentDomain = url.hostname;
                    const ssHeader = 's'+'s';
                    const ssLinks = cfip.map(cdnItem => {
                        let host, port = 443, nodeName = '';
                        if (cdnItem.includes('#')) {
                            const parts = cdnItem.split('#');
                            cdnItem = parts[0];
                            nodeName = parts[1];
                        }
                        if (cdnItem.startsWith('[') && cdnItem.includes(']:')) {
                            const ipv6End = cdnItem.indexOf(']:');
                            host = cdnItem.substring(0, ipv6End + 1);
                            const portStr = cdnItem.substring(ipv6End + 2);
                            port = parseInt(portStr) || 443;
                        } else if (cdnItem.includes(':')) {
                            const parts = cdnItem.split(':');
                            host = parts[0];
                            port = parseInt(parts[1]) || 443;
                        } else {
                            host = cdnItem;
                        }
                        nodeNames.push("    - "+nodeName+"-"+host)
                        return `  - name: ${nodeName+"-"+host}
    server: ${host}
    port: ${port}
    type: ss
    cipher: none
    password: ${password}
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      tls: true
      skip-cert-verify: true
      host: ${currentDomain}
      path: /${password}?ed=2560
      mux: false`
                    });
                    const nodeNamesText=nodeNames.join('\n');
                    const linksText = ssLinks.join('\n\n');
                    const resp = await fetch('https://xjyzs.github.io/tail.yaml');
                    const tail = await resp.text();
                    const finalText=head+linksText+mid+nodeNamesText+'\n'+tail
                    return new Response(finalText, {
                        headers: {
                            'Content-Type': 'text/plain; charset=utf-8',
                            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                            'Content-Disposition': 'attachment; filename="Shadowsocks"',
                        },
                    });
                }
            }
            return new Response(nginxHtml,{
                status: 200,
                headers: {
                    'Content-Type': 'text/html;charset=utf-8',
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                },
            });
        } catch (err) {
            return new Response('Internal Server Error', { status: 500 });
        }
    },
};
