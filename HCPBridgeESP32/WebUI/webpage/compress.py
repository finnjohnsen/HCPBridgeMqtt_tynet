#pip install gzip zlib htmlmin jsmin
#or python -m pip install gzip zlib htmlmin jsmin

print("Compressing WebUI...")

Import("env")
print('Used environment:' + env["PIOENV"])

import gzip

htmlmin = None
try:
    import htmlmin
except ImportError:
    try:
        env.Execute("$PYTHONEXE -m pip install htmlmin")
        import htmlmin
    except Exception:
        print("Warning: htmlmin unavailable (Python 3.14 compat), skipping HTML minification")
try:
    import zlib
except ImportError:
    env.Execute("$PYTHONEXE -m pip install zlib")
    import zlib
jsmin_func = None
try:
    from jsmin import jsmin as jsmin_func
except ImportError:
    try:
        env.Execute("$PYTHONEXE -m pip install jsmin")
        from jsmin import jsmin as jsmin_func
    except Exception:
        print("Warning: jsmin unavailable, skipping JS minification")

content = ""
with open('./WebUI/webpage/index.html','rt',encoding="utf-8") as f:
    content=f.read()


if htmlmin:
    content = htmlmin.minify(content, remove_comments=True, remove_empty_space=True, remove_all_empty_space=True, reduce_empty_attributes=True, reduce_boolean_attributes=False, remove_optional_attribute_quotes=True, convert_charrefs=True, keep_pre=False)


import re
regex = r"<script>(.+?)<\/script>"
if jsmin_func:
    content = re.sub(regex, lambda x: "<script>"+jsmin_func(x.group(1))+"</script>" ,content, 0, re.DOTALL)

result =""
for c in zlib.compress(content.encode("UTF-8"),9):
     result= result + ("0x%02X" %c)
     if len(result)> 0:
          result=result + ","


with open('./WebUI/index_html.h',"wt") as f:
	f.write("const uint8_t index_html[] PROGMEM = {");
	f.write(result.strip(","))
	f.write("};");