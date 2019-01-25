<head>
    <title>"Hey man"</title>
</head>
<body>
<p> vulnerable </p>
<p> notVulnerable </p>
${user}
<%= user %>
<%=t9n.tr(s:'Hi {0}.', f:[user], encoding:"none")%>
<%=t9n.tr(s:'Hi {0}.', f:["${user}"], encoding:"none")%>
<%=t9n.tr(s:'Hi {0}.', f:[user], encoding:"html")%>
</body>

