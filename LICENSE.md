# Licence and terms of use

This course is a free resource. You may read it, run it, copy it, teach from it, translate it, and build on it, commercially or not, under the two licences below. Nothing here requires registration, payment, or permission.

## Summary

| What | Licence | In short |
| --- | --- | --- |
| Code: `reference-lab/`, `targets/`, `instructor/targets/`, `site/`, `deploy/`, and every `.py`, `.html`, `.js`, `.css`, `.json`, `.jsonc` and `.csv` file | MIT | Do what you like; keep the copyright notice; no warranty. |
| Writing: every `.md` file, the module lessons, assessments, answer keys, glossary, media library, templates, and the handbook PDF | Creative Commons Attribution 4.0 International (CC BY 4.0) | Do what you like; credit the source; say if you changed it; no warranty. |
| Third-party material linked or embedded from the course | Its owners' terms | Not covered by either licence above. See "Third-party material". |

Where a file could fall under both rows, the content decides: the spreadsheet templates under `templates/` and the resource catalogue `resources/learning-resources.json` are writing (CC BY 4.0); build scripts and data files that exist only to drive code are code (MIT). The root `LICENSE` file carries the MIT text alone so that code hosts detect it; this file governs.

Attribution that satisfies both licences: "AI Security Engineering: Build, Break, Defend, by Vetrichelvan Jeyapalpandy, used under MIT and CC BY 4.0", with a link to the course website.

## MIT Licence (code)

Copyright (c) 2026 Vetrichelvan Jeyapalpandy

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Creative Commons Attribution 4.0 (writing)

The written material is licensed under the Creative Commons Attribution 4.0 International Licence. You are free to share and adapt it for any purpose, including commercially, as long as you give appropriate credit, link to the licence, and indicate if changes were made. The full legal text is at https://creativecommons.org/licenses/by/4.0/legalcode and a readable summary at https://creativecommons.org/licenses/by/4.0/. The material is provided as is, without warranties of any kind.

## Terms of use

These terms explain how the course is meant to be used. They do not narrow the licences above; they describe the conditions under which the material was written and the responsibilities that stay with you.

**1. Educational purpose.** The course teaches defensive AI security engineering. The targets, the fuzzer, the vulnerable builds and the attack sequences exist so that you can watch a control fail and then fix it. They operate on synthetic data inside your own machine.

**2. Authorised systems only.** Run techniques from this course only against systems you own or have written permission to test. Nothing here authorises testing anyone else's service, model, account or data. The course's own rules of engagement, in `targets/README.md` and in each module, apply to the exercises; the law where you are applies to everything.

**3. No warranty, no guarantee of security.** The reference lab and the hardened reference solutions are teaching artefacts. Passing a grader proves that a specific invariant holds against a specific set of fixtures. It does not make a system secure, and nothing in the course certifies a product, a deployment, or a person. Decisions you make about real systems are yours.

**4. Not professional advice.** The course does not give legal, compliance, employment, or investment advice. Where it discusses regulations, standards or vendor documentation, it summarises public sources listed in `SOURCES.md` with the version and date checked; verify against the current original before relying on it.

**5. No affiliation or endorsement.** The course is independent. It is not affiliated with, sponsored by, or endorsed by OWASP, NIST, DEF CON, Microsoft, NVIDIA, Anthropic, OpenAI, Google, Cloudflare, Lakera, PortSwigger, the UK AI Security Institute, or any other organisation, speaker, author or project it references. Names and marks belong to their owners and are used only to identify the referenced work.

**6. Third-party material.** Recordings, articles, papers, discussion threads, tools and model files that the course links to or plays inline stay under their owners' licences and terms. The course does not copy or host them: YouTube recordings play through YouTube's own embedded player, DEF CON recordings stream from the conference's public archive, and everything else is a link. If you redistribute the course, those items remain links and embeds; do not bundle their content. If an owner wants a reference removed, contact the author and it will be removed.

**7. Your work.** What you write while taking the course, including your hardened targets, milestone evidence, capstone and peer reviews, is yours. The course claims no rights in it. If you contribute changes back to the course, you agree to license them under the same two licences.

**8. Privacy.** The course site keeps your progress in your own browser's local storage and sends nothing anywhere. It sets no analytics, no cookies of its own, and makes no network request except to load the markdown renderer from a public CDN and to play a recording when you press play, at which point the recording's host (YouTube or DEF CON) sees that request under its own privacy policy. If someone else hosts a copy of the site, their hosting platform's logs are theirs to describe; the Cloudflare deployment in this repository enables request observability by default and can be switched off in `deploy/cloudflare/wrangler.jsonc`.

**9. Authorship, accuracy and corrections.** The course was drafted with AI assistance under the author's direction; the README says how. The material was checked on the dates recorded in `VERIFICATION.md` and `MEDIA-LIBRARY.md`. Sources move, tools change, and mistakes happen. Corrections are welcome and will be credited.

**10. Changes to these terms.** These terms may be revised with the course. The version that applies to a copy is the one in that copy's `LICENSE.md`.
