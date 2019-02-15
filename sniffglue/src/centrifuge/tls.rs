use std::str;

use structs::{tls, CentrifugeError};
use tls_parser;
use tls_parser::tls::{TlsMessage, TlsMessageHandshake};
use tls_parser::tls_extensions::{parse_tls_extension, TlsExtension};

pub fn extract(remaining: &[u8]) -> Result<tls::ClientHello, CentrifugeError> {
    if let Ok((_remaining, tls)) = tls_parser::parse_tls_plaintext(remaining) {
        for msg in tls.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
                let mut hostname = None;

                let mut remaining = ch.ext.unwrap();
                while let Ok((remaining2, ext)) = parse_tls_extension(remaining) {
                    remaining = remaining2;
                    if let TlsExtension::SNI(sni) = ext {
                        for s in sni {
                            let name = str::from_utf8(s.1).unwrap();
                            hostname = Some(name.to_owned());
                        }
                    }
                }

                return Ok(tls::ClientHello::new(hostname));
            }
        }

        Err(CentrifugeError::ParsingError)
    } else {
        Err(CentrifugeError::WrongProtocol)
    }
}
