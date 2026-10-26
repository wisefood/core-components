<#-- WiseFood wording for this email; the frame is template.ftl. -->
<#outputformat "plainText">
<#assign requiredActionsText><#if requiredActions??><#list requiredActions><#items as reqActionItem>${msg("requiredAction.${reqActionItem}")}<#sep>, </#sep></#items></#list></#if></#assign>
</#outputformat>
<#import "template.ftl" as layout>
<#assign wfIntro = msg("wfActionsIntro", requiredActionsText)>
<@layout.emailLayout title=msg("wfActionsTitle") preheader=wfIntro>
<@layout.para>${wfIntro}</@layout.para>
<@layout.button label=msg("wfActionsButton") url=link/>
<@layout.para muted=true size=13>${msg("wfLinkExpires", linkExpirationFormatter(linkExpiration))} ${msg("wfActionsIgnore")}</@layout.para>
</@layout.emailLayout>
