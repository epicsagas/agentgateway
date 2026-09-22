//! Probe: replicate the gateway's upstream TLS verification path
//! (rustls-native-certs -> RootCertStore -> rustls handshake) against live hosts.
use std::sync::Arc;

fn handshake(host: &str, roots: &rustls::RootCertStore) -> String {
	let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
	let cfg = rustls::ClientConfig::builder_with_provider(provider)
		.with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
		.expect("versions")
		.with_root_certificates(roots.clone())
		.with_no_client_auth();
	let server = match rustls::pki_types::ServerName::try_from(host.to_string()) {
		Ok(s) => s,
		Err(e) => return format!("dns name error: {e}"),
	};
	let mut conn = match rustls::ClientConnection::new(Arc::new(cfg), server) {
		Ok(c) => c,
		Err(e) => return format!("conn error: {e}"),
	};
	let mut tcp = match std::net::TcpStream::connect((host, 443)) {
		Ok(t) => t,
		Err(e) => return format!("tcp error: {e}"),
	};
	match conn.complete_io(&mut tcp) {
		Ok(_) => format!(
			"HANDSHAKE OK, chain_len={}",
			conn.peer_certificates().map(|c| c.len()).unwrap_or(0)
		),
		Err(e) => {
			let rustls_err = match conn.process_new_packets() {
				Ok(_) => String::new(),
				Err(e2) => format!(" | rustls: {e2}"),
			};
			format!("io err: {e}{rustls_err}")
		},
	}
}

fn main() {
	let result = rustls_native_certs::load_native_certs();
	println!(
		"native certs loaded: {} (errors: {:?})",
		result.certs.len(),
		result.errors
	);
	let mut roots = rustls::RootCertStore::empty();
	let (valid, invalid) = roots.add_parsable_certificates(result.certs.iter().cloned());
	println!("roots: valid={valid} invalid={invalid} total={}", roots.len());

	for host in [
		"stitch.googleapis.com",
		"financial-immune.web.app",
		"api.z.ai",
	] {
		println!("{host}: {}", handshake(host, &roots));
	}
}
