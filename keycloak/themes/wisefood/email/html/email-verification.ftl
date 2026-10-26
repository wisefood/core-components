<#-- WiseFood wording for this email; the frame is template.ftl. -->
<#import "template.ftl" as layout>
<#assign wfIntro = msg("wfVerifyIntro")>
<@layout.emailLayout title=msg("wfVerifyTitle") preheader=wfIntro>
<@layout.para>${wfIntro}</@layout.para>
<@layout.button label=msg("wfVerifyButton") url=link/>
<@layout.para muted=true size=13>${msg("wfLinkExpires", linkExpirationFormatter(linkExpiration))} ${msg("wfVerifyIgnore")}</@layout.para>
</@layout.emailLayout>
