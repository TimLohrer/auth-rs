use dotenv::var;
use lazy_static::lazy_static;
use regex::Regex;
use url::Url;

lazy_static! {
    static ref port_regex: Regex = Regex::new(r":[0-9]+").unwrap();
}

pub fn get_raw_base_domain() -> String {
    match var("PUBLIC_BASE_URL") {
        Ok(url) => {
            let raw_url = port_regex.replace_all(&url, "")
                .replace("http://", "")
                .replace("https://", "")
                .split('/')
                .next()
                .unwrap_or("localhost")
                .to_string();

            if raw_url == "localhost" {
                "localhost".to_string()
            } else {
                let parts: Vec<&str> = raw_url.split('.').collect();
                if parts.len() > 2 {
                    parts[1..].join(".")
                } else {
                    raw_url
                }
            }
        },
        Err(_) => "localhost".to_string(),
    }
}

pub fn get_base_domain() -> String {
    match var("PUBLIC_BASE_URL") {
        Ok(url) => {
            let scheme = url.split("://").next().unwrap_or("http");
            let url_no_port = port_regex.replace_all(&url, "");
            let host = Url::parse(&url_no_port)
                .ok()
                .and_then(|parsed| parsed.host_str().map(|h| h.to_string()))
                .unwrap_or_else(|| "localhost".to_string());
            format!("{}://{}", scheme, host)
        },
        Err(_) => "localhost".to_string(),
    }
}

pub fn get_application_name() -> String {
    let raw_base_domain = get_raw_base_domain();
    let parts: Vec<&str> = raw_base_domain.split('.').collect();
    let name_part = if parts.len() >= 3 {
        // Use second-to-last part for domains with 3+ components
        parts[parts.len() - 2]
    } else if parts.len() == 2 {
        // Use first part for domains with 2 components
        parts[0]
    } else {
        // Use the only part (e.g., "localhost")
        parts[0]
    };
    format!("auth-rs-{}", name_part)
}