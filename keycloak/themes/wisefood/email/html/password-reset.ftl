<#-- WiseFood wording for this email; the frame is template.ftl. -->
<#import "template.ftl" as layout>
<#assign wfIntro = msg("wfResetIntro")>
<@layout.emailLayout title=msg("wfResetTitle") preheader=wfIntro>
<@layout.para>${wfIntro}</@layout.para>
<@layout.button label=msg("wfResetButton") url=link/>
<@layout.para muted=true size=13>${msg("wfLinkExpires", linkExpirationFormatter(linkExpiration))} ${msg("wfResetIgnore")}</@layout.para>
</@layout.emailLayout>
