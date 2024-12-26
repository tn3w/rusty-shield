use serde::Deserialize;
use lazy_static::lazy_static;
use html_escape::encode_text;
use std::{collections::HashMap, sync::RwLock, fs::{File, read_dir}, io::{Result, Read}};

use crate::captcha::{PoW, get_pow};
use crate::utils::{get_domain_host, append_query_prefix};

#[derive(Deserialize, Debug)]
struct Translations {
    #[serde(flatten)]
    pub _translations: HashMap<String, HashMap<String, String>>,
}

lazy_static! {
    static ref TRANSLATIONS: RwLock<HashMap<String, HashMap<String, String>>> = RwLock::new(load_translations().unwrap());
    static ref TEMPLATES: RwLock<HashMap<String, String>> = RwLock::new(load_templates().unwrap());
}

fn load_translations() -> Result<HashMap<String, HashMap<String, String>>> {
    let path = "./assets/translations.json";
    let file = File::open(path)?;
    let translations: HashMap<String, HashMap<String, String>> = serde_json::from_reader(file)?;
    Ok(translations)
}

fn load_templates() -> Result<HashMap<String, String>> {
    let mut templates = HashMap::new();
    
    let template_dir = "./templates";
    let entries = read_dir(template_dir)?;
    
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "html") {
            if let Some(filename) = path.file_name() {
                let filename = filename.to_string_lossy().to_string();
                let mut file = File::open(&path)?;
                let mut content = String::new();
                file.read_to_string(&mut content)?;
                templates.insert(filename, content);
            }
        }
    }

    Ok(templates)
}

fn get_template(template_name: &str) -> Option<String> {
    let templates = TEMPLATES.read().unwrap();
    templates.get(template_name).cloned()
}

fn translate_template(template: Option<String>, lang_code: &str) -> String {
    let mut template = match template {
        Some(t) => t,
        None => return String::new(),
    };

    if lang_code == "en" {
        return template;
    }

    let translations = TRANSLATIONS.read().unwrap();

    for (key, trans_map) in translations.iter() {
        if let Some(translation) = trans_map.get(lang_code) {
            template = template.replace(key, translation);
        }
    }

    template
}

fn render_template(template_name: &str, lang_code: &str, request_url: String) -> String {
    let template = get_template(template_name);
    let mut translated_template = translate_template(template, lang_code);

    translated_template = translated_template.replace("LANGUAGE", &*encode_text(&lang_code));
    translated_template = translated_template.replace("REQUESTURL", &*encode_text(&append_query_prefix(&request_url)));
    let domain = get_domain_host(request_url);
    translated_template = translated_template.replace("DOMAIN", &*encode_text(domain.as_str()));

    translated_template
}

pub fn render_check(lang_code: &str, request_url: String, reason: String) -> String {
    let mut template = render_template("check.html", lang_code, request_url);

    let pow = PoW::new(get_pow(), 5);
    let (challenge, state) = pow.generate_challenge("127.0.0.1");
    template = template.replace("DIFFICULTY", "10");
    template = template.replace("POWCHALLENGE", &*encode_text(&challenge));
    template = template.replace("POWSTATE", &*encode_text(&state));
    template = template.replace("REASON", &*encode_text(&reason));
    template
}

fn render_captcha(lang_code: &str, request_url: String) -> String {
    let template = render_template("captcha.html", lang_code, request_url);
    template
}