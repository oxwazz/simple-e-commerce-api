use url::Url;
use validator::ValidationError;

pub fn validate_url_if_exist(url: &str) -> Result<(), ValidationError> {
    if url.is_empty() {
        return Ok(());
    }
    match Url::parse(url) {
        Ok(_) => Ok(()),
        Err(_) => Err(ValidationError::new("terrible_url")),
    }
}
