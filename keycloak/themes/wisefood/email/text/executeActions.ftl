<#ftl output_format="plainText">
<#outputformat "plainText">
<#assign requiredActionsText><#if requiredActions??><#list requiredActions><#items as reqActionItem>${msg("requiredAction.${reqActionItem}")}<#sep>, </#sep></#items></#list></#if></#assign>
</#outputformat>
${msg("wfActionsTitle")}

${msg("wfActionsIntro", requiredActionsText)}

${link}

${msg("wfLinkExpires", linkExpirationFormatter(linkExpiration))}
${msg("wfActionsIgnore")}

--
${msg("wfFooterNote")}
(c) ${.now?string("yyyy")} ${msg("wfConsortium")} - ${msg("wfEuAlt")}
