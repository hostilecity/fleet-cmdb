# Markup that must always be rendered escaped: a script element and an event-handler attribute. Shared by the
# escaping specs, and defined once here so loading several spec files never redefines it (#69).
HOSTILE = %(<script>alert("x")</script><img src=x onerror=alert(1)>).freeze
