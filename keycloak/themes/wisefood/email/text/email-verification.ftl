<#ftl output_format="plainText">
${msg("wfVerifyTitle")}

${msg("wfVerifyIntro")}

${link}

${msg("wfLinkExpires", linkExpirationFormatter(linkExpiration))}
${msg("wfVerifyIgnore")}

--
${msg("wfFooterNote")}
(c) ${.now?string("yyyy")} ${msg("wfConsortium")} - ${msg("wfEuAlt")}
