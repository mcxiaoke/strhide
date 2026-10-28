pub mod commands;
pub mod state;

use state::GuiState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(GuiState::default())
        .invoke_handler(tauri::generate_handler![
            commands::diag::get_capabilities_cmd,
            commands::diag::inspect_carrier_cmd,
            commands::diag::verify_carrier_cmd,
            commands::diag::scan_carrier_cmd,
            commands::structure::write_structure_file_cmd,
            commands::structure::read_structure_file_cmd,
            commands::structure::restore_structure_file_cmd,
            commands::stego::probe_stego_capacity_cmd,
            commands::stego::embed_stego_file_cmd,
            commands::stego::extract_stego_file_cmd,
            commands::stego::smart_extract_cmd,
            commands::batch::set_ui_language_cmd,
            commands::batch::cancel_task_cmd,
            commands::batch::run_batch_job_cmd,
        ])
        .run(tauri::generate_context!())
        .expect("error while running strhide studio application");
}
