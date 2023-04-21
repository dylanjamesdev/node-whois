import * as _ from 'underscore';
import * as net from 'net';
import { SocksClient } from 'socks';
import * as punycode from 'punycode';
import * as util from 'util';
const SERVERS = require('./servers.json');

const cleanParsingErrors = (string: string): string =>
  string.replace(/^[:\s]+/, '').replace(/^https?[:\/]+/, '') || string;

export const lookup = (
  addr: string,
  options: { follow?: number; timeout?: number; server?: string | { host: string; port: number; query: string }; proxy?: string | { ipaddress: string; port: number; type?: number }; encoding?: string; punycode?: boolean; verbose?: boolean; bind?: string },
  done: (err: Error | null, result?: any) => void
): void => {
  if (typeof done === 'undefined' && typeof options === 'function') {
    done = options;
    options = {};
  }

  if (addr === '__proto__') {
    done(new Error('lookup: __proto__ is not allowed to lookup'));
    return;
  }

  _.defaults(options, {
    follow: 2,
    timeout: 60000, // 60 seconds in ms
  });

  done = _.once(done);

  let server = options.server;
  const proxy = options.proxy;
  const timeout = options.timeout;

  if (!server) {
    switch (true) {
      case _.contains(addr, '@'):
        done(new Error('lookup: email addresses not supported'));
        return;

      case net.isIP(addr) !== 0:
        server = SERVERS['_']['ip'];
        break;

      default:
        let tld = punycode.toASCII(addr);
        while (true) {
          server = SERVERS[tld];
          if (!tld || server) {
            break;
          }
          tld = tld.replace(/^.+?(\.|$)/, '');
        }
    }
  }

  if (!server) {
    done(new Error('lookup: no whois server is known for this kind of object'));
    return;
  }

  if (typeof server === 'string') {
    const parts = server.split(':');
    server = {
      host: parts[0],
      port: parseInt(parts[1], 10),
      query: '$addr\r\n',
    };
  }

  if (typeof proxy === 'string') {
    const parts = proxy.split(':');
    proxy = {
      ipaddress: parts[0],
      port: parseInt(parts[1], 10),
    };
  }

  _.defaults(server, {
    port: 43,
    query: '$addr\r\n',
  });

  if (proxy) {
    _.defaults(proxy, {
      type: 5,
    });
  }

  const _lookup = (socket: net.Socket, done: (err: Error | null, result?: any) => void): void => {
    let idn = addr;
    if (server!.punycode !== false && options.punycode !== false) {
      idn = punycode.toASCII(addr);
    }
    if (options.encoding) {
      socket.setEncoding(options.encoding);
    }
    socket.write(server!.query.replace('$addr', idn));

    let data = '';
    socket.on('data', (chunk) => {
      data += chunk;
    });

    socket.on('timeout', () => {
      socket.destroy();
      done(new Error('lookup: timeout'));
    });


    socket.on('error', (err) => {
      done(err);
    });

socket.on('close', (err) => {
      if (options.follow > 0) {
        const match = data.replace(/\r/gm, '').match(/(ReferralServer|Registrar Whois|Whois Server|WHOIS Server|Registrar WHOIS Server|refer):[^\S\n]*((?:r?whois|https?):\/\/)?([0-9A-Za-z\.\-_]*)/);
        if (match && match[3] != server.host) {
          options = {
            ...options,
            follow: options.follow - 1,
            server: match[3].trim()
          };
          options.server = cleanParsingErrors(options.server);
          lookup(addr, options, (err, parts) => {
            if (err) {
              return done(err);
            }
            if (options.verbose) {
              done(null, [
                {
                  server: (typeof server === 'object') ? server.host.trim() : server.trim(),
                  data: data
                },
                ...parts
              ]);
            } else {
              done(null, parts);
            }
          });
          return;
        }
      }
      if (options.verbose) {
        done(null, [
          {
            server: (typeof server === 'object') ? server.host.trim() : server.trim(),
            data: data
          }
        ]);
      } else {
        done(null, data);
      }
    });

    if (!Number.isInteger(server.port)) {
      server.port = 43;
    }

    if (proxy) {
      SocksClient.createConnection({
        proxy: proxy,
        destination: {
          host: server.host,
          port: server.port
        },
        command: 'connect',
        timeout: timeout
      }, (err, info) => {
        if (err) {
          return done(err);
        }
        const { socket } = info;
        if (timeout) {
          socket.setTimeout(timeout);
        }

        _lookup(socket, done);

        socket.resume();
      });
    } else {
      const sockOpts = {
        host: server.host,
        port: server.port
      };
      if (options.bind) {
        sockOpts.localAddress = options.bind;
      }
      const socket = net.connect(sockOpts);
      if (timeout) {
        socket.setTimeout(timeout);
      }
      _lookup(socket, done);
    }
  };

