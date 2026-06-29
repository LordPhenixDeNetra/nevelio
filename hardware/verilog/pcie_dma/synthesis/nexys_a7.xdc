# Nevelio Hardware Security — Contraintes Xilinx (XDC)
# Cible : Nexys A7-35T / 100T  (xc7a35ticsg324-1L / xc7a100tcsg324-1)
#
# IMPORTANT : Les contraintes PCIe réelles dépendent du core IP Xilinx PCIe
# et de la carte de développement. Ces contraintes couvrent :
#   - Horloge système 100 MHz
#   - UART de débogage (via FTDI FT2232HQ)
#   - GPIO LEDs/Buttons
#   - Contraintes PCIe (à adapter selon le slot)

# ══════════════════════════════════════════════════════════════════════════════
# Horloge principale — 100 MHz (oscillateur embarqué Nexys A7)
# ══════════════════════════════════════════════════════════════════════════════

set_property -dict {
    PACKAGE_PIN E3
    IOSTANDARD  LVCMOS33
} [get_ports clk]

create_clock -period 10.000 -name sys_clk_100 [get_ports clk]

# ══════════════════════════════════════════════════════════════════════════════
# Reset actif bas (bouton CPU_RESET sur la Nexys A7)
# ══════════════════════════════════════════════════════════════════════════════

set_property -dict {
    PACKAGE_PIN C12
    IOSTANDARD  LVCMOS33
} [get_ports rst_n]

# ══════════════════════════════════════════════════════════════════════════════
# LEDs (indicateurs d'état DMA)
# LED0 = scan_start, LED1 = scan_done, LED2 = erreur
# ══════════════════════════════════════════════════════════════════════════════

set_property -dict {PACKAGE_PIN H17 IOSTANDARD LVCMOS33} [get_ports {led[0]}]
set_property -dict {PACKAGE_PIN K15 IOSTANDARD LVCMOS33} [get_ports {led[1]}]
set_property -dict {PACKAGE_PIN J13 IOSTANDARD LVCMOS33} [get_ports {led[2]}]
set_property -dict {PACKAGE_PIN N14 IOSTANDARD LVCMOS33} [get_ports {led[3]}]
set_property -dict {PACKAGE_PIN R18 IOSTANDARD LVCMOS33} [get_ports {led[4]}]
set_property -dict {PACKAGE_PIN V17 IOSTANDARD LVCMOS33} [get_ports {led[5]}]
set_property -dict {PACKAGE_PIN U17 IOSTANDARD LVCMOS33} [get_ports {led[6]}]
set_property -dict {PACKAGE_PIN U16 IOSTANDARD LVCMOS33} [get_ports {led[7]}]

# ══════════════════════════════════════════════════════════════════════════════
# UART (FT2232HQ — USB Serial, canal B)
# Utilisé pour : transfert des données DMA lues vers le PC hôte
# ══════════════════════════════════════════════════════════════════════════════

set_property -dict {PACKAGE_PIN D4 IOSTANDARD LVCMOS33} [get_ports uart_tx]
set_property -dict {PACKAGE_PIN C4 IOSTANDARD LVCMOS33} [get_ports uart_rx]

# ══════════════════════════════════════════════════════════════════════════════
# PCIe (M.2 ou connecteur PCIe selon variante de la carte)
# Les noms de broches PCIe dépendent de l'IP Xilinx utilisée.
#
# Pour Nexys A7 avec FMC PCIe (Digilent PCIe FMC) :
# NOTE : Les contraintes PCIe GTP sont gérées automatiquement par l'IP Xilinx.
#        Décommenter uniquement si vous utilisez un slot PCIe externe via FMC.
# ══════════════════════════════════════════════════════════════════════════════

# Horloge de référence PCIe 100 MHz (depuis connecteur PCIe)
# set_property -dict {PACKAGE_PIN F6 IOSTANDARD LVDS} [get_ports pcie_clk_p]
# set_property -dict {PACKAGE_PIN E6 IOSTANDARD LVDS} [get_ports pcie_clk_n]

# create_clock -period 10.000 -name pcie_refclk [get_ports pcie_clk_p]

# Différentiel PCIe RX/TX (GTP transceivers — Artix-7)
# set_property PACKAGE_PIN B6 [get_ports {pcie_rx_p[0]}]
# set_property PACKAGE_PIN B5 [get_ports {pcie_rx_n[0]}]
# set_property PACKAGE_PIN A4 [get_ports {pcie_tx_p[0]}]
# set_property PACKAGE_PIN A3 [get_ports {pcie_tx_n[0]}]

# ══════════════════════════════════════════════════════════════════════════════
# False Paths (homoloques asynchrones)
# ══════════════════════════════════════════════════════════════════════════════

# Reset asynchrone → faux chemin vers les bascules
set_false_path -from [get_ports rst_n]

# ══════════════════════════════════════════════════════════════════════════════
# Timing Constraints — Relaxations Debug
# ══════════════════════════════════════════════════════════════════════════════

# DMA completion interface — moins critique (pas sur le chemin critique)
set_multicycle_path -setup 2 -from [get_cells *rd_data*] -to [get_cells *scan_done*]
set_multicycle_path -hold  1 -from [get_cells *rd_data*] -to [get_cells *scan_done*]

# ══════════════════════════════════════════════════════════════════════════════
# Configuration bitstream (sécurité)
# ══════════════════════════════════════════════════════════════════════════════

set_property BITSTREAM.CONFIG.SPI_BUSWIDTH 4          [current_design]
set_property BITSTREAM.CONFIG.CONFIGRATE  33          [current_design]
set_property CONFIG_VOLTAGE               3.3         [current_design]
set_property CFGBVS                       VCCO        [current_design]
# Chiffrement AES-256 du bitstream (nécessite clé eFUSE programmée)
# set_property BITSTREAM.ENCRYPTION.ENCRYPT YES        [current_design]
# set_property BITSTREAM.ENCRYPTION.KEYFILE design.nky [current_design]
