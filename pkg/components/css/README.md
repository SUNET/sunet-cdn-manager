# How to fetch the pico.min.css
Based on https://picocss.com/docs#install-manually
```
pico_version="2.1.1"
curl -LO https://github.com/picocss/pico/archive/refs/tags/v${pico_version}.zip
unzip -d dist v${pico_version}.zip pico-${pico_version}/css/pico.min.css
rm ${pico_version}.zip
```

# pico-settings.css
Local tweaks to pico settings

# console-grid.css
Management of the grid layout of the overall console app
