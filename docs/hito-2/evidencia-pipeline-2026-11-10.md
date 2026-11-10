# Evidencia del pipeline en `main`

La corrida [DevSecOps #42869527875](https://github.com/mar22266/proyecto-final-desarrollo/actions/runs/42869527875) corresponde al merge `617694f` del 10 de noviembre de 2026. Terminó con estado `success` y publicó los cuatro artefactos esperados.

| Control | Job | Artefacto |
|---|---|---|
| SAST | SAST (Semgrep) | [semgrep](https://github.com/mar22266/proyecto-final-desarrollo/actions/runs/42869527875/artifacts/13788134170) |
| SCA | SCA (dependencias) | [sca](https://github.com/mar22266/proyecto-final-desarrollo/actions/runs/42869527875/artifacts/13789495683) |
| SBOM | SBOM (Syft, CycloneDX) | [sbom.cdx.json](https://github.com/mar22266/proyecto-final-desarrollo/actions/runs/42869527875/artifacts/13789705156) |
| DAST | DAST (ZAP baseline) | [zap](https://github.com/mar22266/proyecto-final-desarrollo/actions/runs/42869527875/artifacts/13789785404) |

El artefacto SBOM publicado tiene tamaño de 25.8 KB y el digest SHA-256 mostrado por Actions es `26f878da8f2645e91cff4abb1c9311e7ab3f0e657031939be0c621fe78f2500d`. La página de la corrida muestra los cuatro jobs terminados correctamente. El gate está configurado en modo `reporte`, por lo que el estado verde confirma la ejecución y publicación de evidencia, no la remediación de todos los hallazgos.

Enlaces directos para obtener las capturas solicitadas en Canvas: [resumen de la corrida](https://github.com/mar22266/proyecto-final-desarrollo/actions/runs/42869527875) y [sección de artefactos, incluido el SBOM](https://github.com/mar22266/proyecto-final-desarrollo/actions/runs/42869527875#artifacts).
