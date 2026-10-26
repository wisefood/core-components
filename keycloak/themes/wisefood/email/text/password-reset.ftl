<#ftl output_format="plainText">
${msg("wfResetTitle")}

${msg("wfResetIntro")}

${link}

${msg("wfLinkExpires", linkExpirationFormatter(linkExpiration))}
${msg("wfResetIgnore")}

--
${msg("wfFooterNote")}
(c) ${.now?string("yyyy")} ${msg("wfConsortium")} - ${msg("wfEuAlt")}
