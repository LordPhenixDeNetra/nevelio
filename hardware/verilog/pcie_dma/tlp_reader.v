// Nevelio Hardware Security — PCIe TLP Memory Read Request
// Compatible : Xilinx PCIe IP (7 Series / UltraScale), PCILeech architecture
// FPGA cible  : Artix-7 (Nexys A7-35T ou 100T)
//
// Description :
//   Ce module génère des TLP (Transaction Layer Packet) Memory Read Request
//   vers l'hôte PCIe pour lire la mémoire physique à des fins d'audit DMA.
//   Basé sur l'architecture PCILeech-FPGA (https://github.com/ufrisk/pcileech-fpga).
//
// Protocole AXI-Stream vers le core PCIe Xilinx (s_axis_tx / m_axis_rx).
//
// Utilisation légale : audit de sécurité DMA autorisé (IOMMU bypass testing).

`timescale 1ns / 1ps

// ── Constantes TLP ──────────────────────────────────────────────────────────

// TLP Type : Memory Read Request (32-bit address)
`define TLP_MEM_RD32    7'b0000000
// TLP Type : Memory Read Request (64-bit address)
`define TLP_MEM_RD64    7'b0100000
// Attributs par défaut : pas de relaxed ordering, pas de No-Snoop
`define TLP_ATTR_DEFAULT 3'b000
// Traffic Class : TC0 (best effort)
`define TLP_TC_DEFAULT  3'b000

// ── Module principal ─────────────────────────────────────────────────────────

module tlp_reader #(
    // Bus ID PCIe (Requester ID)
    parameter [15:0] REQUESTER_ID  = 16'h0100,
    // Taille max d'un TLP (en double words)
    parameter [9:0]  MAX_PAYLOAD   = 10'd64,
    // Taille max d'une requête de lecture (en double words)
    parameter [9:0]  MAX_READ_REQ  = 10'd512
)(
    // ── Horloge et reset ────────────────────────────────────────────────────
    input  wire        clk,
    input  wire        rst_n,

    // ── Interface utilisateur ────────────────────────────────────────────────
    // Requête de lecture DMA
    input  wire [63:0] rd_addr,       // adresse physique à lire
    input  wire [9:0]  rd_len_dw,     // longueur en double words (1–512)
    input  wire        rd_valid,      // requête valide
    output wire        rd_ready,      // module prêt à accepter
    // Données lues (completion)
    output reg  [63:0] rd_data,       // données retournées (premier DW)
    output reg         rd_data_valid, // données disponibles
    output reg  [2:0]  rd_status,     // statut completion (0=OK, 1=UR, 2=CA)

    // ── Interface AXI-Stream TX (vers PCIe core) ─────────────────────────────
    input  wire        tx_rdy,
    output reg  [63:0] tx_data,
    output reg         tx_sop,        // start of packet
    output reg         tx_eop,        // end of packet
    output reg         tx_valid,
    output reg         tx_keep,

    // ── Interface AXI-Stream RX (depuis PCIe core — completions) ─────────────
    input  wire [63:0] rx_data,
    input  wire        rx_sop,
    input  wire        rx_eop,
    input  wire        rx_valid,

    // ── Statistiques ────────────────────────────────────────────────────────
    output reg  [31:0] stat_tlp_sent,
    output reg  [31:0] stat_cpl_recv,
    output reg  [31:0] stat_errors
);

// ── FSM états ────────────────────────────────────────────────────────────────

localparam ST_IDLE       = 3'd0;
localparam ST_HEADER1    = 3'd1;   // premier DW du header TLP
localparam ST_HEADER2    = 3'd2;   // deuxième DW (Requester ID + Tag + Last/First BE)
localparam ST_ADDR_LO    = 3'd3;   // adresse 32-bit bas (ou 64-bit lo)
localparam ST_ADDR_HI    = 3'd4;   // adresse 64-bit haut (si nécessaire)
localparam ST_WAIT_CPL   = 3'd5;   // attente completion
localparam ST_PARSE_CPL  = 3'd6;   // décodage completion
localparam ST_DONE       = 3'd7;

reg [2:0] state;
reg [2:0] next_state;

// Registres internes
reg [63:0] r_addr;
reg [9:0]  r_len_dw;
reg [7:0]  r_tag;          // tag courant (0–255)
reg        r_addr64;        // 1 si adresse > 32-bit

// Tag counter
reg [7:0]  tag_counter;

assign rd_ready = (state == ST_IDLE);

// ── Machine d'état ─────────────────────────────────────────────────────────

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        state         <= ST_IDLE;
        tx_valid      <= 1'b0;
        tx_sop        <= 1'b0;
        tx_eop        <= 1'b0;
        tx_data       <= 64'b0;
        tx_keep       <= 1'b0;
        rd_data_valid <= 1'b0;
        rd_data       <= 64'b0;
        rd_status     <= 3'b0;
        stat_tlp_sent <= 32'b0;
        stat_cpl_recv <= 32'b0;
        stat_errors   <= 32'b0;
        tag_counter   <= 8'b0;
        r_addr64      <= 1'b0;
    end else begin
        case (state)

        // ── IDLE — attente requête ────────────────────────────────────────
        ST_IDLE: begin
            tx_valid      <= 1'b0;
            tx_sop        <= 1'b0;
            tx_eop        <= 1'b0;
            rd_data_valid <= 1'b0;
            if (rd_valid && tx_rdy) begin
                r_addr    <= rd_addr;
                r_len_dw  <= rd_len_dw;
                r_tag     <= tag_counter;
                r_addr64  <= (rd_addr[63:32] != 32'b0);
                tag_counter <= tag_counter + 1;
                state     <= ST_HEADER1;
            end
        end

        // ── HEADER 1 — Format / Type / Length ────────────────────────────
        // DW0 : FMT[2:0] | TYPE[4:0] | TC[2:0] | TD | EP | ATTR[2:0] | AT | Length[9:0]
        ST_HEADER1: begin
            if (tx_rdy) begin
                tx_sop   <= 1'b1;
                tx_valid <= 1'b1;
                tx_keep  <= 1'b1;
                tx_data  <= {
                    // Byte 0 : FMT[2:1]=00 (3DW), Type=MRd32 si 32-bit
                    (r_addr64 ? 3'b001 : 3'b000),    // FMT
                    (r_addr64 ? `TLP_MEM_RD64 : `TLP_MEM_RD32), // Type
                    1'b0,                              // T9
                    `TLP_TC_DEFAULT,                   // TC
                    1'b0,                              // T8
                    1'b0,                              // TD (no digest)
                    1'b0,                              // EP (not poisoned)
                    `TLP_ATTR_DEFAULT,                 // ATTR
                    2'b00,                             // AT
                    r_len_dw[9:0],                    // Length
                    // DW1 sera envoyé au prochain cycle (pipeline)
                    32'b0
                };
                tx_sop  <= 1'b1;
                state   <= ST_HEADER2;
            end
        end

        // ── HEADER 2 — Requester ID + Tag + Byte Enable ──────────────────
        // DW1 : Requester ID[15:0] | Tag[7:0] | Last DW BE[3:0] | First DW BE[3:0]
        ST_HEADER2: begin
            if (tx_rdy) begin
                tx_sop  <= 1'b0;
                tx_data <= {
                    REQUESTER_ID,   // 16 bits
                    r_tag,          //  8 bits
                    4'hf,           //  Last DW BE : tous actifs
                    4'hf,           //  First DW BE : tous actifs
                    32'b0           //  padding (sera remplacé par adresse)
                };
                state <= r_addr64 ? ST_ADDR_LO : ST_ADDR_LO;
            end
        end

        // ── ADRESSE (32 ou 64-bit) ────────────────────────────────────────
        // DW2 : Address[31:2] | Reserved[1:0]
        ST_ADDR_LO: begin
            if (tx_rdy) begin
                if (r_addr64) begin
                    // 64-bit : DW2 = addr[63:32], DW3 = addr[31:2]|00
                    tx_data <= {r_addr[63:32], r_addr[31:2], 2'b00};
                    tx_eop  <= 1'b1;  // 4DW header (64-bit) : eop ici
                end else begin
                    tx_data <= {r_addr[31:2], 2'b00, 32'b0};
                    tx_eop  <= 1'b1;  // 3DW header (32-bit) : eop ici
                end
                tx_valid      <= 1'b0;
                stat_tlp_sent <= stat_tlp_sent + 1;
                state         <= ST_WAIT_CPL;
            end
        end

        // ── ATTENTE COMPLETION ────────────────────────────────────────────
        ST_WAIT_CPL: begin
            tx_eop   <= 1'b0;
            tx_valid <= 1'b0;
            if (rx_valid && rx_sop) begin
                // Détecter completion correspondant à notre tag
                // Byte 0 : FMT=010, Type=01010 (CplD), ...
                // Byte 1 : Status[2:0] dans les bits [15:13] du DW1
                state <= ST_PARSE_CPL;
            end
        end

        // ── DÉCODAGE COMPLETION ───────────────────────────────────────────
        ST_PARSE_CPL: begin
            if (rx_valid) begin
                // DW2 : Completer ID[15:0] | Status[2:0] | BCM | Byte Count[11:0]
                rd_status     <= rx_data[46:44];  // Completion Status
                rd_data       <= rx_data;
                rd_data_valid <= 1'b1;
                stat_cpl_recv <= stat_cpl_recv + 1;

                if (rx_data[46:44] != 3'b000) begin
                    // Unsuccessful Completion ou CA
                    stat_errors <= stat_errors + 1;
                end

                if (rx_eop)
                    state <= ST_DONE;
            end
        end

        // ── DONE ─────────────────────────────────────────────────────────
        ST_DONE: begin
            rd_data_valid <= 1'b0;
            state         <= ST_IDLE;
        end

        default: state <= ST_IDLE;
        endcase
    end
end

endmodule


// ── DMA Controller — séquence de lecture continue ──────────────────────────

module dma_controller #(
    parameter [15:0] REQUESTER_ID = 16'h0100,
    parameter [63:0] DEFAULT_BASE = 64'h0000_0000_0000_0000,
    parameter [31:0] CHUNK_BYTES  = 32'h0000_1000  // 4KB par requête
)(
    input  wire        clk,
    input  wire        rst_n,

    // Configuration
    input  wire [63:0] scan_base,    // adresse de début du scan
    input  wire [63:0] scan_size,    // nombre d'octets à lire
    input  wire        scan_start,   // lancer le scan
    output reg         scan_done,    // scan terminé

    // Interface vers tlp_reader
    output reg  [63:0] rd_addr,
    output reg  [9:0]  rd_len_dw,
    output reg         rd_valid,
    input  wire        rd_ready,
    input  wire [63:0] rd_data,
    input  wire        rd_data_valid,
    input  wire [2:0]  rd_status,

    // Interface TX/RX (pass-through vers tlp_reader)
    input  wire        tx_rdy,
    output wire [63:0] tx_data,
    output wire        tx_sop,
    output wire        tx_eop,
    output wire        tx_valid,
    output wire        tx_keep,
    input  wire [63:0] rx_data,
    input  wire        rx_sop,
    input  wire        rx_eop,
    input  wire        rx_valid,

    // Statistiques
    output reg  [63:0] bytes_read,
    output reg  [31:0] errors
);

localparam DMA_IDLE    = 2'd0;
localparam DMA_READING = 2'd1;
localparam DMA_WAIT    = 2'd2;
localparam DMA_DONE    = 2'd3;

reg [1:0]  dma_state;
reg [63:0] cur_addr;
reg [63:0] remaining;

tlp_reader #(.REQUESTER_ID(REQUESTER_ID)) tlp_rd (
    .clk         (clk),
    .rst_n       (rst_n),
    .rd_addr     (rd_addr),
    .rd_len_dw   (rd_len_dw),
    .rd_valid    (rd_valid),
    .rd_ready    (rd_ready),
    .rd_data     (rd_data),
    .rd_data_valid(rd_data_valid),
    .rd_status   (rd_status),
    .tx_rdy      (tx_rdy),
    .tx_data     (tx_data),
    .tx_sop      (tx_sop),
    .tx_eop      (tx_eop),
    .tx_valid    (tx_valid),
    .tx_keep     (tx_keep),
    .rx_data     (rx_data),
    .rx_sop      (rx_sop),
    .rx_eop      (rx_eop),
    .rx_valid    (rx_valid)
);

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        dma_state  <= DMA_IDLE;
        scan_done  <= 1'b0;
        bytes_read <= 64'b0;
        errors     <= 32'b0;
        rd_valid   <= 1'b0;
    end else begin
        case (dma_state)
        DMA_IDLE: begin
            scan_done <= 1'b0;
            if (scan_start) begin
                cur_addr  <= scan_base;
                remaining <= scan_size;
                dma_state <= DMA_READING;
            end
        end

        DMA_READING: begin
            if (remaining == 0) begin
                dma_state <= DMA_DONE;
            end else if (rd_ready) begin
                rd_addr   <= cur_addr;
                // Taille de la requête : min(CHUNK_BYTES, remaining) en DWs
                rd_len_dw <= (remaining >= CHUNK_BYTES)
                             ? (CHUNK_BYTES >> 2)
                             : (remaining[11:2]);
                rd_valid  <= 1'b1;
                dma_state <= DMA_WAIT;
            end
        end

        DMA_WAIT: begin
            rd_valid <= 1'b0;
            if (rd_data_valid) begin
                if (rd_status != 3'b000)
                    errors <= errors + 1;
                else begin
                    cur_addr   <= cur_addr + CHUNK_BYTES;
                    bytes_read <= bytes_read + CHUNK_BYTES;
                    remaining  <= (remaining >= CHUNK_BYTES)
                                  ? (remaining - CHUNK_BYTES)
                                  : 64'b0;
                end
                dma_state <= DMA_READING;
            end
        end

        DMA_DONE: begin
            scan_done <= 1'b1;
            dma_state <= DMA_IDLE;
        end
        endcase
    end
end

endmodule
