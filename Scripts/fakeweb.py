mkdir -p /tmp/web_falso
cat > /tmp/web_falso/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>ITLA - Sitio Falso</title></head>
<body style="background:red;color:white;text-align:center">
<h1>SITIO FALSO - ATAQUE DNS SPOOFING</h1>
<h2>Matricula: 20211150</h2>
<h2>Alvaro Smilk Baez Tavera</h2>
<p>Este sitio simula itla.edu.do</p>
<p>Servidor real redirigido a: 20.21.11.50</p>
</body>
</html>
EOF
cd /tmp/web_falso
python3 -m http.server 80
