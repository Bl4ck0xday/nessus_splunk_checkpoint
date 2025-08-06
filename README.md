# Nessus Splunk Checkpoint

![Nessus + Splunk](images/nessussplunk.png)

---

## 📌 Descripción

**Nessus Splunk Checkpoint** es un script en Python que permite enviar los resultados de escaneos de vulnerabilidades desde **Nessus Professional** hacia **Splunk**, utilizando HEC (HTTP Event Collector).  
El script evita duplicaciones usando un archivo de checkpoint local (`checkpoint.json`) que registra qué plugins ya fueron enviados por host y por escaneo.

---

## ⚙️ Pre-requisitos

- Python 3.8 o superior.
- Token HEC de Splunk habilitado.
- Llaves de acceso (Access Key y Secret Key) del API de Nessus Professional.
- Conexión de red entre tu servidor y los servicios de Splunk y Nessus.

> Las variables `HEC_TOKEN`, `N_ACCESS_KEY` y `N_SECRET_KEY` pueden definirse mediante:
> - Variables de entorno (recomendado para mayor seguridad), o  
> - El archivo `servers.json` incluido como plantilla en el repositorio.

---

## ▶️ Cómo usarlo

1. Clona el repositorio:
```bash
git clone https://github.com/Bl4ck0xday/nessus_splunk_checkpoint.git
cd nessus_splunk_checkpoint
```

2. Instala las dependencias:
```bash
pip install -r requirements.txt
```

3. Configura tus credenciales en el archivo `servers.json` **o** define las variables de entorno:
```bash
export HEC_TOKEN="tu_token_hec"
export N_ACCESS_KEY="tu_access_key"
export N_SECRET_KEY="tu_secret_key"
```

4. Ejecuta el script:
```bash
python3 nessus_splunk_checkpoint.py
```

---

## 💡 Recomendaciones

- Asegúrate de tener escaneos configurados en Nessus con una periodicidad adecuada a tus necesidades (por ejemplo, diarios o semanales).
- Puedes usar `cron` (Linux) o el Programador de Tareas (Windows) para automatizar la ejecución del script y enviar vulnerabilidades recién detectadas a Splunk de manera continua.

---

## 👤 Autor

**Francis Segura**  
[LinkedIn](https://www.linkedin.com/in/francis-segura-22a0191a8/)

---

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Ver el archivo [LICENSE](LICENSE) para más detalles.