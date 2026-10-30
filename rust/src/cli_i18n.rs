//! Localization traverser for clap Command tree.

use crate::core::i18n::{Lang, Msg};
use clap::Command;

/// Recursively traverse and update the Command's about, after_help, and argument helps.
pub fn localize(mut cmd: Command, lang: Lang) -> Command {
    walk(&mut cmd, lang);
    cmd
}

fn walk(cmd: &mut Command, lang: Lang) {
    let name = cmd.get_name().to_string();

    if let Some(t) = cmd_about(&name, lang) {
        *cmd = std::mem::take(cmd).about(t);
    }
    if let Some(t) = cmd_after_help(&name, lang) {
        *cmd = std::mem::take(cmd).after_help(t);
    }

    let arg_ids: Vec<String> = cmd
        .get_arguments()
        .map(|a| a.get_id().as_str().to_string())
        .collect();
    for id in arg_ids {
        if let Some(t) = arg_help(&name, &id, lang) {
            *cmd = std::mem::take(cmd).mut_arg(&id, |arg| arg.help(t).long_help(t));
        }
    }

    for sub in cmd.get_subcommands_mut() {
        walk(sub, lang);
    }
}

fn cmd_about(name: &str, lang: Lang) -> Option<&'static str> {
    let msg = match name {
        // The three domain entry points share the root about text; their
        // subcommand names are unchanged, so all subcommand help stays shared.
        "strhide" | "sth" | "sthc" | "sths" | "sthv" => Msg::CmdRoot,
        "write" => Msg::CmdWrite,
        "read" => Msg::CmdRead,
        "restore" => Msg::CmdRestore,
        "inspect" => Msg::CmdInspect,
        "verify" => Msg::CmdVerify,
        "scan" => Msg::CmdScan,
        "embed" => Msg::CmdEmbed,
        "capacity" => Msg::CmdCapacity,
        "extract" => Msg::CmdExtract,
        "list" => Msg::CmdList,
        _ => return None,
    };
    Some(msg.text(lang))
}

fn cmd_after_help(name: &str, lang: Lang) -> Option<&'static str> {
    let msg = match name {
        "strhide" | "sth" => Msg::AfterHelpRoot,
        "write" => Msg::AfterHelpWrite,
        "read" => Msg::AfterHelpRead,
        "embed" => Msg::AfterHelpEmbed,
        "capacity" => Msg::AfterHelpCapacity,
        "extract" => Msg::AfterHelpExtract,
        "restore" => Msg::AfterHelpRestore,
        "inspect" => Msg::AfterHelpInspect,
        "verify" => Msg::AfterHelpVerify,
        "scan" => Msg::AfterHelpScan,
        _ => return None,
    };
    Some(msg.text(lang))
}

fn arg_help(cmd: &str, raw_id: &str, lang: Lang) -> Option<&'static str> {
    let id_str = raw_id.replace('_', "-");
    let id = id_str.as_str();
    let msg = match (cmd, id) {
        // Root options
        ("strhide" | "sth" | "sthc" | "sths" | "sthv", "config") => Msg::HelpRootConfig,
        ("strhide" | "sth" | "sthc" | "sths" | "sthv", "quiet") => Msg::HelpRootQuiet,
        ("strhide" | "sth" | "sthc" | "sths" | "sthv", "lang") => Msg::HelpRootLang,

        // Built-in clap help / version on any level
        (_, "help") => Msg::HelpBuiltinHelp,
        (_, "version") => Msg::HelpBuiltinVersion,

        // Shared / flattened options (matched by id across commands)
        (_, "password") => Msg::HelpSharedPassword,
        (_, "password-file") => Msg::HelpSharedPasswordFile,
        (_, "data") => Msg::HelpSharedData,
        (_, "text") => Msg::HelpSharedText,
        (_, "file") => Msg::HelpSharedFile,
        (_, "stdin") => Msg::HelpSharedStdin,
        (_, "text-file") => Msg::HelpSharedTextFile,
        (_, "text-base64") => Msg::HelpSharedTextBase64,

        // Stego options: one wording for embed / capacity, except where the
        // command context changes the meaning (the capacity probe has its own
        // carrier wording). The specific commands must be matched before the
        // wildcard arms.
        (_, "algorithm") => Msg::HelpStegoAlgorithm,
        (_, "safety") => Msg::HelpEmbedSafety,
        (_, "enforce-safety") => Msg::HelpEmbedEnforceSafety,
        (_, "exclusion-rate") => Msg::HelpEmbedExclusionRate,
        (_, "neighbor-weight") => Msg::HelpStegoNeighborWeight,
        (_, "p1-window") => Msg::HelpStegoP1Window,
        (_, "p2-window") => Msg::HelpStegoP2Window,
        (_, "stc-h") => Msg::HelpStegoStcH,
        (_, "slot-budget") => Msg::HelpStegoSlotBudget,
        (_, "cipher-suite") => Msg::HelpStegoCipherSuite,
        ("embed", "capacity") => Msg::HelpEmbedCapacity,
        ("embed", "dry-run") => Msg::HelpEmbedDryRun,
        ("capacity", "carrier") => Msg::HelpCapacityCarrier,
        ("capacity", "json") => Msg::HelpCapacityJson,

        // write
        ("write", "carrier") => Msg::HelpWriteCarrier,
        ("write", "output") => Msg::HelpWriteOutput,
        ("write", "in-place") => Msg::HelpWriteInPlace,
        ("write", "overwrite") => Msg::HelpWriteOverwrite,
        ("write", "strategy") => Msg::HelpWriteStrategy,
        ("write", "stealth") => Msg::HelpWriteStealth,
        ("write", "encrypt") => Msg::HelpWriteEncrypt,
        ("write", "no-encrypt") => Msg::HelpWriteNoEncrypt,
        ("write", "hint") => Msg::HelpWriteHint,
        ("write", "preserve-time") => Msg::HelpWriteNoPreserveTime,
        ("write", "no-preserve-time") => Msg::HelpWriteNoPreserveTime,
        ("write", "no-backup") => Msg::HelpWriteNoBackup,
        (_, "unescape") => Msg::HelpWriteUnescape,
        (_, "exact") => Msg::HelpExact,

        // read
        ("read", "carrier") => Msg::HelpReadCarrier,
        ("read", "output") => Msg::HelpReadOutput,
        ("read", "stdout") => Msg::HelpReadStdout,
        ("read", "overwrite") => Msg::HelpReadOverwrite,

        // restore
        ("restore", "carrier") => Msg::HelpRestoreCarrier,
        ("restore", "output") => Msg::HelpRestoreOutput,
        ("restore", "in-place") => Msg::HelpRestoreInPlace,
        ("restore", "overwrite") => Msg::HelpRestoreOverwrite,
        ("restore", "no-backup") => Msg::HelpRestoreNoBackup,

        // inspect
        ("inspect", "carrier") => Msg::HelpInspectCarrier,
        ("inspect", "recursive") => Msg::HelpInspectRecursive,
        ("inspect", "json") => Msg::HelpInspectJson,

        // verify
        ("verify", "carrier") => Msg::HelpVerifyCarrier,
        ("verify", "recursive") => Msg::HelpVerifyRecursive,
        ("verify", "json") => Msg::HelpVerifyJson,

        // scan
        ("scan", "input") => Msg::HelpScanInput,
        ("scan", "recursive") => Msg::HelpScanRecursive,
        ("scan", "json") => Msg::HelpScanJson,

        // embed
        ("embed", "carrier") => Msg::HelpEmbedCarrier,
        ("embed", "output") => Msg::HelpEmbedOutput,
        ("embed", "in-place") => Msg::HelpEmbedInPlace,
        ("embed", "overwrite") => Msg::HelpEmbedOverwrite,
        ("embed", "no-backup") => Msg::HelpEmbedNoBackup,
        ("embed", "encrypt") => Msg::HelpEmbedEncrypt,

        // extract
        ("extract", "carrier") => Msg::HelpExtractCarrier,
        ("extract", "output") => Msg::HelpExtractOutput,
        ("extract", "stdout") => Msg::HelpExtractStdout,
        ("extract", "overwrite") => Msg::HelpExtractOverwrite,

        // list
        ("list", "json") => Msg::HelpListJson,

        _ => return None,
    };
    Some(msg.text(lang))
}
