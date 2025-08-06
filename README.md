# nessus_splunk_checkpoint

**Autor:** Francis Segura · [LinkedIn](https://www.linkedin.com/in/francissegura/)

**Herramienta en Python** que extrae resultados de escaneos de Nessus Professional y los envía a Splunk mediante HEC, evitando duplicaciones a través de un checkpoint local.

---

## Objetivo

- Procesar únicamente escaneos con estado `"completed"` desde Nessus.  
- Enviar solo nuevas vulnerabilidades (`plugin_id`) por host y scan.  
- Utilizar un punto de guardado local (`checkpoint.json`) para evitar reenvíos.

---

## Requisitos

- Python 3.8 o superior.  
- Reemplaza tus variables en el `servers.json` con tus valores reales.  


