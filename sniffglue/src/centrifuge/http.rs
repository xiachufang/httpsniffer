use nom_http;

use structs::http::Request;
use structs::CentrifugeError;

pub fn extract(remaining: &[u8]) -> Result<Request, CentrifugeError> {
    if let Ok((remaining, (request, headers))) = nom_http::request(remaining) {
        match Request::from_nom(&request, headers, remaining) {
            Ok(http) => Ok(http),
            Err(_) => Err(CentrifugeError::ParsingError),
        }
    } else {
        Err(CentrifugeError::WrongProtocol)
    }
}
