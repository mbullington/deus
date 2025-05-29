const SAFE_PATH: &str = "/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin";

fn main() {
    if option_env!("SAFE_PATH").is_none() {
        println!("cargo:rustc-env=SAFE_PATH={SAFE_PATH}")
    }
}
