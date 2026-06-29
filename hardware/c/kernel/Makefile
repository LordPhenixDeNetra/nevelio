# Nevelio Hardware Security — Kernel Modules Build
# Compatibilité : Linux kernel 5.x et 6.x
#
# Usage :
#   make          # compile tous les modules
#   make lime     # compile uniquement lime_wrapper.ko
#   make msr      # compile uniquement msr_reader.ko
#   make clean    # nettoyer les artifacts de compilation
#   make install  # charger les modules (root requis)
#   make unload   # décharger les modules
#
# Prérequis :
#   sudo apt-get install linux-headers-$(uname -r) build-essential

KDIR  ?= /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

# Modules à compiler
obj-m += lime_wrapper.o
obj-m += msr_reader.o

.PHONY: all lime msr clean install unload

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

lime:
	$(MAKE) -C $(KDIR) M=$(PWD) lime_wrapper.ko

msr:
	$(MAKE) -C $(KDIR) M=$(PWD) msr_reader.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@rm -f modules.order Module.symvers

install: all
	@echo "[nevelio] Chargement des modules..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "ERREUR : root requis. Utiliser : sudo make install"; exit 1; \
	fi
	-sudo insmod lime_wrapper.ko path=/tmp/nevelio_memory.lime format=lime
	-sudo insmod msr_reader.ko
	@echo "[nevelio] Modules chargés. Voir : dmesg | grep nevelio"

unload:
	@echo "[nevelio] Déchargement des modules..."
	-sudo rmmod lime_wrapper 2>/dev/null || true
	-sudo rmmod msr_reader   2>/dev/null || true
	@echo "[nevelio] Modules déchargés."

# Vérification des headers kernel
check-headers:
	@if [ ! -d "$(KDIR)" ]; then \
		echo "ERREUR : headers kernel introuvables : $(KDIR)"; \
		echo "Installer : sudo apt-get install linux-headers-$(shell uname -r)"; \
		exit 1; \
	fi
	@echo "[nevelio] Headers kernel : $(KDIR) — OK"
