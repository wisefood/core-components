<#ftl output_format="plainText">
${msg("wfUpdateEmailTitle")}

${msg("wfUpdateEmailIntro", newEmail)}

${link}

${msg("wfLinkExpires", linkExpirationFormatter(linkExpiration))}
${msg("wfUpdateEmailIgnore")}

--
${msg("wfFooterNote")}
(c) ${.now?string("yyyy")} ${msg("wfConsortium")} - ${msg("wfEuAlt")}
