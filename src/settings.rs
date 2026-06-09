use env_settings_derive::EnvSettings;
use serde;

#[derive(EnvSettings, Clone, serde::Serialize)]
#[env_settings(case_insensitive, delay)]
pub(crate) struct Settings {
    #[env_settings(default = "Generic File Host")]
    pub name: String,

    pub database_url: String,

    pub base_url: Option<String>,

    #[env_settings(default = "127.0.0.1")]
    pub listen_addr: String,
    #[env_settings(default = 8080)]
    pub listen_port: u16,

    #[env_settings(default = 512)]
    pub max_filesize: usize, //max. filesize in mib
    #[env_settings(default = 180)]
    pub max_fileage: usize, //max. age of files in days
    #[env_settings(default = 31)]
    pub min_fileage: usize, //min. age of files in days
    #[env_settings(default = 2)]
    pub decay_exp: usize, //high values penalise larger files more

    #[env_settings(default = 300)]
    pub upload_timeout: usize, //max. time an upload can take before it times out
    #[env_settings(default = 3)]
    pub min_id_length: usize, //min. length of the random file id
    #[env_settings(default = 24)]
    pub max_id_length: usize, //max. length of the random file id, set to min_id_length to disable
    #[env_settings(default = "files/")]
    pub store_path: String, //directory to store uploaded files in
    pub log_path: Option<String>, //path to log uploads + resulting links to
    #[env_settings(default = 7)]
    pub max_ext_len: usize, //max. length for file extensions
    #[env_settings(default = "false")]
    pub auto_file_ext: bool, //automatically try to detect file extension for files that have none
    #[env_settings(default = "false")]
    pub trust_xff: bool, //trust X-Forwarded-For header; enable only when behind a reverse proxy

    #[env_settings(default = "admin@example.com")]
    pub admin_email: String,

    pub clamd_addr: Option<String>,
}
