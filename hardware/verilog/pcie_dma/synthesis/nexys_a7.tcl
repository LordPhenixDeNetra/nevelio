# Nevelio Hardware Security — Vivado Synthesis Script
# Cible : Nexys A7-35T (xc7a35ticsg324-1L) ou Nexys A7-100T (xc7a100tcsg324-1)
#
# Usage :
#   vivado -mode batch -source synthesis/nexys_a7.tcl
#   (avec la variable BOARD optionnelle : -tclargs nexys_a7_35 | nexys_a7_100)

# ── Configuration ────────────────────────────────────────────────────────────

set PART_35T  "xc7a35ticsg324-1L"
set PART_100T "xc7a100tcsg324-1"
set BOARD     [lindex $argv 0]

if {$BOARD eq "nexys_a7_100"} {
    set PART $PART_100T
    set PROJ "nevelio_dma_100t"
} else {
    set PART $PART_35T
    set PROJ "nevelio_dma_35t"
}

set TOP_MODULE "dma_controller"
set RTL_DIR    "[file dirname [file normalize [info script]]]/.."
set OUT_DIR    "[file dirname [file normalize [info script]]]/output"

file mkdir $OUT_DIR

puts "╔══════════════════════════════════════════════════════════════╗"
puts "║  Nevelio Hardware Security — PCIe DMA FPGA Synthesis        ║"
puts "║  Part   : $PART"
puts "║  Projet : $PROJ"
puts "╚══════════════════════════════════════════════════════════════╝"

# ── Création du projet ───────────────────────────────────────────────────────

create_project $PROJ $OUT_DIR/$PROJ -part $PART -force

set_property board_part digilentinc.com:nexys-a7-100t:part0:1.3 [current_project]

# ── Sources RTL ──────────────────────────────────────────────────────────────

add_files -norecurse [list \
    "$RTL_DIR/tlp_reader.v" \
]

set_property file_type {Verilog} [get_files *.v]
set_property top $TOP_MODULE [current_fileset]

# ── Contraintes ──────────────────────────────────────────────────────────────

add_files -fileset constrs_1 -norecurse "$RTL_DIR/synthesis/nexys_a7.xdc"

# ── IP PCIe Xilinx (7 Series Integrated Block for PCI Express) ──────────────

# NOTE : Décommenter et adapter si le core PCIe IP est disponible dans la licence
# create_ip -name pcie_7x -vendor xilinx.com -library ip -version 3.3 -module_name pcie_7x_0
# set_property -dict [list \
#     CONFIG.Max_Link_Width {X1} \
#     CONFIG.Link_Speed {2.5_GT/s} \
#     CONFIG.Bar0_Scale {Megabytes} \
#     CONFIG.Bar0_Size {1} \
#     CONFIG.Device_ID {0x1234} \
#     CONFIG.Vendor_ID {0x10EE} \
# ] [get_ips pcie_7x_0]
# generate_target all [get_ips pcie_7x_0]

# ── Synthèse ─────────────────────────────────────────────────────────────────

puts "\n[*] Lancement de la synthèse..."
synth_design \
    -top      $TOP_MODULE \
    -part     $PART \
    -flatten_hierarchy rebuilt \
    -directive PerformanceOptimized

report_utilization -file "$OUT_DIR/utilization_synth.rpt"
report_timing_summary -file "$OUT_DIR/timing_synth.rpt" -max_paths 10

# ── Optimisation ─────────────────────────────────────────────────────────────

puts "\n[*] Optimisation..."
opt_design

# ── Placement ────────────────────────────────────────────────────────────────

puts "\n[*] Placement..."
place_design -directive EarlyBlockPlacement
phys_opt_design

# ── Routage ──────────────────────────────────────────────────────────────────

puts "\n[*] Routage..."
route_design -directive AggressiveExplore

report_route_status -file "$OUT_DIR/route_status.rpt"
report_timing_summary -file "$OUT_DIR/timing_impl.rpt" \
    -max_paths 50 -nworst 5 -warn_on_violation

report_utilization -file "$OUT_DIR/utilization_impl.rpt"
report_power -file "$OUT_DIR/power.rpt"

# ── Vérification timing ──────────────────────────────────────────────────────

set wns [get_property SLACK [get_timing_paths -max_paths 1 -nworst 1 -setup]]
if {$wns < 0} {
    puts "ATTENTION : Timing non satisfait (WNS = $wns ns)"
    puts "           Vérifier les contraintes dans nexys_a7.xdc"
}

# ── Génération du bitstream ──────────────────────────────────────────────────

puts "\n[*] Génération du bitstream..."
write_bitstream \
    -force \
    "$OUT_DIR/${PROJ}.bit"

write_debug_probes \
    -force \
    "$OUT_DIR/${PROJ}.ltx"

# ── Rapport final ────────────────────────────────────────────────────────────

puts "\n╔══════════════════════════════════════════════════════════════╗"
puts "║  SYNTHÈSE TERMINÉE                                          ║"
puts "╠══════════════════════════════════════════════════════════════╣"
puts "║  Bitstream : $OUT_DIR/${PROJ}.bit"
puts "║  Rapports  : $OUT_DIR/"
puts "╚══════════════════════════════════════════════════════════════╝"

# ── Téléchargement (optionnel — décommenter pour programmer le FPGA) ─────────

# open_hw_manager
# connect_hw_server
# open_hw_target
# set_property PROGRAM.FILE "$OUT_DIR/${PROJ}.bit" [get_hw_devices xc7a*]
# program_hw_devices [get_hw_devices xc7a*]
# close_hw_manager
