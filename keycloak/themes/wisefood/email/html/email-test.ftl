<#-- WiseFood wording for this email; the frame is template.ftl. -->
<#import "template.ftl" as layout>
<@layout.emailLayout title=msg("wfTestTitle") preheader=msg("wfTestIntro")>
<@layout.para>${msg("wfTestIntro")}</@layout.para>
</@layout.emailLayout>
