use file_format::FileFormat;
use head_tail_reader::HeadTailReader;

mod associations;
mod head_tail_reader;

// External file, do not complain about lint
#[allow(dead_code)]
mod sanitize_filename;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileGroup {
    Image,
    Photo,
    VectorImage,
    Video,
    Audio,
    Key,
    Text,
    Calendar,
    Pdf,
    Word,
    PowerPoint,
    Excel,
    Document,
    Unknown,
}

pub fn get_mime_type_from_content(input: &[u8]) -> String {
    let format = FileFormat::from_bytes(input);
    adapt(format.media_type())
}

pub fn get_mime_type_from_head_and_tail(head: &[u8], tail: &[u8], total_len: u64) -> String {
    let reader = HeadTailReader::new(head, tail, total_len);
    let format = FileFormat::from_reader(reader).unwrap_or(FileFormat::ArbitraryBinaryData);
    adapt(format.media_type())
}

pub fn get_file_group_from_mime_type(mime_type: &str) -> FileGroup {
    let as_lower = mime_type.to_lowercase();
    let decoded = associations::FILE_GROUP_MAP
        .get(&as_lower)
        .cloned()
        .unwrap_or(FileGroup::Unknown);

    if FileGroup::Unknown == decoded {
        get_file_group_from_heuristics(&as_lower)
    } else {
        decoded
    }
}

fn adapt(media_type: &str) -> String {
    match media_type {
        "application/mp4" => "video/mp4",
        "video/x-msvideo" => "video/avi",
        _ => media_type,
    }
    .to_string()
}

fn get_file_group_from_heuristics(mime_type: &str) -> FileGroup {
    let first_part = mime_type.split('/').next().unwrap_or("");
    match first_part {
        "image" => FileGroup::Image,
        "video" => FileGroup::Video,
        "audio" => FileGroup::Audio,
        "text" => FileGroup::Text,
        _ => FileGroup::Unknown,
    }
}

pub fn sanitize_name(name: &str, windows: bool) -> String {
    let options = sanitize_filename::Options {
        windows,
        truncate: true, // Truncates to 255 bytes
        replacement: "",
    };
    sanitize_filename::sanitize_with_options(name, options)
}
