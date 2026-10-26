<#--
  The WiseFood email frame, for every HTML email Keycloak sends.

  Mirrors wisefood-api/src/email_layout.py so a verification mail, a password
  reset and a reminder from the platform read as the same sender: the logo on
  a white page, a white card, one button, the consortium footer with the EU
  emblem. White and neutral greys only: Gmail's apps and Outlook darken light
  colours in dark mode but keep their hue, and the old warm cream page
  arrived brown. Table layout and inline styles because mail clients are
  not browsers; the <style> block only adds what inline styles cannot reach
  (the base message HTML of the emails this theme does not reword, and the
  phone breakpoint).
-->
<#macro emailLayout title="" preheader="">
<#assign wfLang = (locale.language)!"en">
<!doctype html>
<html lang="${wfLang}" xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="x-apple-disable-message-reformatting">
<meta name="color-scheme" content="light only">
<meta name="supported-color-schemes" content="light only">
<title>${title}</title>
<style>
  :root { color-scheme: light only; }
  body { margin:0; padding:0; background:#ffffff; }
  a { color:#aa2944; }
  .wf-body p { margin:0 0 14px; font-size:15px; line-height:1.6; color:#3d4148; }
  @media (max-width:620px) {
    .wf-outer { padding:20px 8px !important; }
    .wf-pad { padding:28px 22px !important; }
  }
</style>
</head>
<body style="margin:0;padding:0;background:#ffffff;">
<#if preheader?has_content><div style="display:none;max-height:0;max-width:0;overflow:hidden;opacity:0;mso-hide:all;color:#ffffff;font-size:1px;line-height:1px;">${preheader}&#8199;&#847;&#8199;&#847;&#8199;&#847;&#8199;&#847;</div></#if>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#ffffff;">
<tr><td class="wf-outer" align="center" style="padding:32px 12px;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:600px;">
<tr><td align="center" style="padding:0 0 24px;"><a href="${properties.wfAppUrl}" target="_blank" rel="noopener" style="text-decoration:none;"><img src="${properties.wfLogoUrl}" width="210" alt="WiseFood" style="display:block;border:0;outline:none;width:210px;max-width:210px;height:auto;"></a></td></tr>
<tr><td style="background:#ffffff;border:1px solid #e4e4e7;border-radius:16px;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
<tr><td class="wf-pad wf-body" style="padding:36px 40px 30px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.6;color:#3d4148;">
<#if title?has_content><h1 style="margin:0 0 18px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:22px;line-height:1.3;font-weight:600;color:#1d2125;">${title}</h1></#if>
<#nested>
</td></tr>
</table>
</td></tr>
<tr><td align="center" style="padding:26px 20px 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:12px;line-height:1.6;color:#80858d;">
<p style="margin:0 0 8px;">${msg("wfFooterNote")}</p>
<p style="margin:0 0 14px;">&copy; ${.now?string("yyyy")} ${msg("wfConsortium")}</p>
<a href="${properties.wfCordisUrl}" target="_blank" rel="noopener" style="text-decoration:none;"><img src="${properties.wfEuUrl}" width="150" alt="${msg("wfEuAlt")}" style="display:inline-block;border:0;outline:none;width:150px;height:auto;"></a>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
</#macro>

<#-- One body paragraph. -->
<#macro para muted=false size=15><p style="margin:0 0 14px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:${size}px;line-height:1.6;color:<#if muted>#80858d<#else>#3d4148</#if>;"><#nested></p></#macro>

<#-- The button, and the plain link beneath it for clients that drop it. -->
<#macro button label url>
<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:26px 0 10px;border-collapse:separate;">
<tr><td align="center" bgcolor="#d53355" style="border-radius:10px;background:#d53355;"><a href="${url}" target="_blank" rel="noopener" style="display:inline-block;padding:13px 26px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:15px;font-weight:600;line-height:1.2;color:#ffffff;text-decoration:none;border-radius:10px;">${label}</a></td></tr>
</table>
<p style="margin:0 0 18px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:12px;line-height:1.5;color:#80858d;">${msg("wfButtonFallback")}<br><a href="${url}" style="color:#80858d;word-break:break-all;">${url}</a></p>
</#macro>
