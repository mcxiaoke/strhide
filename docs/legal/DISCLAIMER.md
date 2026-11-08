# Disclaimer

> This is the disclaimer for **StrHide / `strhide`**. The Chinese version is [DISCLAIMER.zh.md](DISCLAIMER.zh.md).
> **Both language versions are provided; where they differ, the Chinese version prevails.**
> Last updated: 2026-11-08

---

## 0. Read this first

`strhide` is a **data-hiding and steganography tool**. It works by modifying the actual bytes of your files: the content domain rewrites pixels, DCT coefficients, HEVC bitstream sign bits, or audio samples; the structure domain injects an envelope into container structures. That means **it can damage your files**, and some of those changes cannot be undone.

If you do not agree with any part of this disclaimer, do not download, install, copy, or use this project.

**Do three things before you start:**

1. **Back up.** Keep an independent copy of every file you intend to process, somewhere this tool cannot reach.
2. **Check your rights.** Only process files you own or are explicitly authorized to modify.
3. **Check the law.** Confirm that possessing and using a tool of this kind — and the material you intend to hide — is lawful in your jurisdiction.

---

## 1. What this software is, and what it is for

1.1 This is an **open-source research project**, not a commercial product and not a hosted service. It comes with no service-level commitment, no availability guarantee, and no support obligation.

1.2 Intended uses: research on steganography and format-preserving engineering; teaching and demonstration; academic experiments; CTF and security competitions; experimental digital watermarking and copyright marking; technical validation of personal-privacy techniques; and lawful, authorized methodology research in forensics and anti-forensics.

1.3 **Explicitly outside the intended scope**: long-term storage of confidential data in production; the only copy of a credential or key; archives that must pass a compliance audit; and any high-risk setting involving life safety, medical care, financial transactions, judicial evidence, or industrial control. For those, use a purpose-built, audited solution.

1.4 **This is not a secure communication system.** Steganography is not encryption: without a password, any official build can read the payload (see the design boundaries in [SECURITY.md](../../.github/SECURITY.md)); and even with a password, `--stealth` and private dialects do not improve resistance to statistical steganalysis. If you need confidentiality, use a mature encryption scheme and evaluate your own threat model ([docs/THREAT_MODEL.md](../THREAT_MODEL.md)).

---

## 2. Prohibited uses

You **must not** use this project for any of the following.

**2.1 Violating the law**
- Any use that breaches applicable laws, regulations, or binding rules in your jurisdiction;
- creating, distributing, or storing illegal or harmful material, including malware, ransomware, trojans, or phishing material;
- network attacks, unauthorized access, or damaging computer systems or data;
- fraud, money laundering, gambling, trade-secret theft, or other criminal or unlawful conduct.

**2.2 Infringing the rights of others**
- Violating privacy, personal-data rights, copyright, trademark, or other intellectual property;
- parsing, extracting, modifying, or distributing someone else's files or data without authorization;
- breaching a contract, a duty of confidence, or a platform's terms of service.

**2.3 Undermining the authenticity of files and records (directly relevant to what this tool does)**
- Modifying files belonging to another person or organization without authorization;
- tampering with contracts, vouchers, invoices, logs, audit records, surveillance material, or any material with evidentiary value;
- creating the appearance that a file is unmodified, or misleading anyone about a file's origin or integrity;
- obstructing or evading a judicial, regulatory, internal, or incident investigation, or a compliance audit;
- circumventing statutory duties relating to data retention, audit trails, tamper-evidence, or electronic signatures.

**2.4 Circumventing security mechanisms**
- Defeating digital rights management (DRM), license checks, access controls, or similar technical measures;
- evading content moderation, platform abuse detection, endpoint security (AV/EDR), or network monitoring.

**2.5 Malicious use**
- Concealing, delivering, or transporting malicious code or its configuration;
- building covert channels for command-and-control, data theft, or lateral movement;
- any form of unauthorized access or data exfiltration.

If we become aware that this project is being used for such purposes, we reserve the right to decline support, state the situation publicly, or report it to the competent authorities. Whether we exercise that right is at our sole discretion and creates no obligation.

---

## 3. Your responsibility

3.1 You are **solely responsible** for everything you do with this software and for all consequences, including legal liability, financial loss, and claims by third parties.

3.2 You are responsible for establishing that possessing and using a steganography tool is permitted where you are; that the data you process was lawfully obtained; and that you hold the necessary authorization from your employer, client, data subjects, or rights holders.

3.3 If you use this project on behalf of an organization, you confirm that you are authorized to do so and that you have completed the applicable compliance and security review yourself.

3.4 We **do not control, monitor, or have visibility into** how you use the software. The project contains no telemetry and transmits nothing (see the implementation properties in [SECURITY.md](../../.github/SECURITY.md)), so we are neither informed about nor able to intervene in your specific use.

---

## 4. Data risk and your backup obligation (the most important section)

4.1 **Content-domain edits (`embed`, or "stego" in the desktop app) are irreversible.** Once pixels, DCT coefficients, bitstream sign bits, or audio samples are rewritten, no original bytes remain to roll back to. No tool can restore the file.

4.2 **The structure domain's bit-exact restore (`write`, or "embed" in the desktop app) only holds while the carrier is untouched.** After a re-encode, recompression, second embed, "save as", or platform transcode, `restore` fails closed with `RestoreMismatch`. That is a **deliberate safety failure**, not a bug to work around.

4.3 **You must make your own backups.** The `.bak` file that `--in-place` creates is a convenience, not a backup: it can be overwritten, forgotten, synced to a cloud account, quarantined by antivirus, or left half-written when the disk fills. **The desktop app creates no backup at all** (it writes to a target directory with `backup: false`). Treating "there is a .bak" as "my data is safe" is exactly the mistake this paragraph exists to prevent.

4.4 **Do not use it to hold the only copy of anything.** Do not hide your only password, key, certificate, private key, or recovery code as a payload; do not let a modified file become the only surviving version of that file.

4.5 **We cannot recover your data.** We do not provide data-recovery services and do not promise to diagnose or repair a damaged file. Errors you encounter (`RestoreMismatch`, `CorruptedData`, `PayloadTooLarge`, `NoHiddenData`, …) are conclusions, not a queue of tickets waiting to be resolved.

4.6 **Compatibility is not guaranteed.** Players, image viewers, office suites, cloud drives, social platforms, CDNs, and mail gateways may re-encode, strip, refuse to open, or flag modified files. Whether a carrier survives a trip through a third-party service is yours to verify.

4.7 **Interruption risk.** A killed process, power loss, full disk, locked file, or two concurrent writes to the same target can leave incomplete output or a leftover temporary file (`.strhide.<pid>.<r>.tmp`). Process important files in a stable environment.

---

## 5. File integrity, signatures, and detection

5.1 The tool **refuses** signed carriers (PE Authenticode, PDF `ByteRange` signatures, signed JARs), because any injection invalidates the signature. That refusal is a protection, not a missing feature. Do not route around it with another tool and then process the file here.

5.2 Every modification changes the file's **hash, checksum, and fingerprint**. Downstream systems that compare hashes — build verification, chain of evidence, compliance archives, deduplicating backups, content-addressed storage — will consider the file "modified". That is often an unacceptable side effect; decide before you write.

5.3 Steganographic and encrypted content **may trigger antivirus, EDR, mail-gateway, or cloud content scanners**, resulting in alerts, quarantine, or deletion. This is normal for the category, not a defect in this project, and we accept no liability for losses it causes.

5.4 `scan` produces **heuristic judgments**, not evidence. "Nothing found" does not prove a file is clean, and "suspicious" does not prove malicious intent. Do not base an adverse decision about another person on this tool's automated output.

---

## 6. No warranty

The software is provided **"AS IS"**, without warranty or condition of any kind, express or implied, including merchantability, fitness for a particular purpose, title, non-infringement, and error-free operation (see also Apache-2.0 §§7–8 in [LICENSE](../../LICENSE)).

We do not warrant that: the software is available or free of defects; results are correct; a hidden payload will be extractable; a failed extraction means a wrong password; a carrier is undetectable; performance matches any expectation; the software interoperates with any particular tool, platform, or file-format version; or that wire formats will remain readable across releases.

---

## 7. Limitation of liability

**To the maximum extent permitted by applicable law**, the authors, maintainers, contributors, and distributors are not liable for any direct, indirect, incidental, special, punitive, or consequential damages arising from the use of, or inability to use, this project, including without limitation: loss or corruption of data, unreadable files, business interruption, lost profits or revenue, damaged equipment, third-party claims, administrative penalties, criminal exposure, reputational harm, or legal fees — even if advised of the possibility of such damages.

This section does **not** exclude liability that cannot be excluded under applicable law (for example, damage caused intentionally or by gross negligence), and does **not** limit rights granted to you by mandatory consumer-protection rules in your jurisdiction. If your jurisdiction does not allow certain warranties to be excluded or liabilities limited, those clauses apply there only to the minimum extent necessary, and the remaining clauses stay in force.

---

## 8. Indemnity

To the extent permitted by applicable law, you agree to indemnify and hold us harmless from any claim, damage, loss, liability, and expense (including reasonable legal fees) arising from your use or misuse of this software, including any breach of this disclaimer, any violation of law, or any infringement of a third party's rights.

---

## 9. No support obligation

This project is maintained by volunteers. We make no commitment regarding response times, fix deadlines, continued availability of any feature, or answers to any particular question. Security reports follow [SECURITY.md](../../.github/SECURITY.md); general channels are listed in [SUPPORT.md](../../.github/SUPPORT.md). Support is offered in good faith and is not a contractual obligation.

---

## 10. Third-party components, algorithms, and marks

10.1 The cost models and embedding methods implemented here (HILL, S-UNIWARD, MiPOD, UERD, J-UNIWARD, J-MiPOD, …) come from published research; the methods themselves are public knowledge. The parameter choices and engineering in this reference implementation are this project's responsibility.

10.2 **H.265/HEVC is subject to standard-essential patents.** MIT/Apache-2.0 grant copyright licenses, not patent licenses. Assess that before distributing a build with `content-hevc` enabled. See [LEGAL.md](LEGAL.md) §4.

10.3 Third-party components and their licenses are listed in [THIRD_PARTY_LICENSES.md](../licenses/THIRD_PARTY_LICENSES.md) and under [`docs/licenses/`](../licenses/).

10.4 Third-party product names, formats, and trademarks mentioned here (PNG, JPEG, H.265/HEVC, Tauri, …) belong to their respective owners and are used only for technical description and interoperability. No affiliation, sponsorship, or endorsement is implied.

---

## 11. Export control and cryptography

The project contains cryptographic functionality (PBKDF2, HKDF, AES-256-GCM, ChaCha20-Poly1305) that is subject to export-control or use restrictions in some jurisdictions. Compliance is your responsibility; see [LEGAL.md](LEGAL.md) §3.

---

## 12. Acceptance, changes, and interpretation

12.1 **Downloading, installing, copying, modifying, or otherwise using this project constitutes acceptance of this disclaimer in full.**

12.2 We may update this disclaimer at any time. Material changes are recorded in [CHANGELOG.md](../../CHANGELOG.md) and reflected in the date at the top of this file. Continued use after a change constitutes acceptance; re-read it before relying on the tool.

12.3 If any clause is held invalid or unenforceable by a competent authority, that clause is restricted or removed to the minimum extent necessary and the remaining clauses remain in full force.

12.4 Our failure or delay in exercising any right under this disclaimer is not a waiver of that right.

12.5 This disclaimer is not legal advice. If your situation involves compliance, employment, evidentiary, or cross-border requirements, consult a qualified lawyer.

---

## 13. Contact

- Legal, licensing, or content-removal requests: `mcxiaoke@live.com`
- Security vulnerabilities: **do not** open a public issue — use the private channel in [SECURITY.md](../../.github/SECURITY.md).
