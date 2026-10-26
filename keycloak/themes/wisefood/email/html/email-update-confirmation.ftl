<#-- WiseFood wording for this email; the frame is template.ftl. -->
<#import "template.ftl" as layout>
<#assign wfIntro = msg("wfUpdateEmailIntro", newEmail)>
<@layout.emailLayout title=msg("wfUpdateEmailTitle") preheader=wfIntro>
<@layout.para>${wfIntro}</@layout.para>
<@layout.button label=msg("wfUpdateEmailButton") url=link/>
<@layout.para muted=true size=13>${msg("wfLinkExpires", linkExpirationFormatter(linkExpiration))} ${msg("wfUpdateEmailIgnore")}</@layout.para>
</@layout.emailLayout>
