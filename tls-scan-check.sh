#!/bin/bash

output_dir="scan_results"
mkdir -p "$output_dir"

menu() {
  clear
  echo "====== MENU TLS SCAN ======"
  echo "1) Rodar coleta de domínios (subfinder & assetfinder)"
  echo "2) Rodar SSLScan nos domínios"
  echo "3) Gerar CSV Final"
  echo "4) Sair"
  echo "==========================="
  read -p "Escolha uma opção: " opt
  case $opt in
    1) coleta_dominio ;;
    2) rodar_sslscan ;;
    3) gerar_csv ;;
    4) exit ;;
    *) echo "Opção inválida!" ; sleep 2 ; menu ;;
  esac
}

coleta_dominio() {
  read -p "Digite o domínio alvo (ex: target.com): " target

  echo "[*] Rodando subfinder..."
  subfinder -d "$target" -silent -o "$output_dir/subfinder.txt"

  echo "[*] Rodando assetfinder..."
  assetfinder --subs-only "$target" > "$output_dir/assetfinder.txt"

  echo "[*] Comparando resultados..."
  sort -u "$output_dir/subfinder.txt" > "$output_dir/subfinder_sorted.txt"
  sort -u "$output_dir/assetfinder.txt" > "$output_dir/assetfinder_sorted.txt"

  comm -23 "$output_dir/subfinder_sorted.txt" "$output_dir/assetfinder_sorted.txt" > "$output_dir/unicos_subfinder.txt"
  comm -13 "$output_dir/subfinder_sorted.txt" "$output_dir/assetfinder_sorted.txt" > "$output_dir/unicos_assetfinder.txt"
  comm -12 "$output_dir/subfinder_sorted.txt" "$output_dir/assetfinder_sorted.txt" > "$output_dir/comum.txt"

  echo "[*] Gerando lista final de domínios únicos..."
  cat "$output_dir/subfinder_sorted.txt" "$output_dir/assetfinder_sorted.txt" | sort -u > "$output_dir/final_domains.txt"
  echo "[*] Total de domínios encontrados: $(wc -l < "$output_dir/final_domains.txt")"
  sleep 2
  menu
}

rodar_sslscan() {
  if [ ! -f "$output_dir/final_domains.txt" ]; then
    echo "[-] Nenhum domínio encontrado. Rode a coleta primeiro."
    sleep 2
    menu
  fi

  echo "[*] Rodando sslscan em cada domínio..."
  while read -r domain; do
    ip=$(dig +short "$domain" | head -n1)
    [ -z "$ip" ] && echo "$domain sem IP resolvido, pulando..." && continue

    sslscan --no-color "$domain" > "$output_dir/${domain}_sslscan.txt"
    echo "$domain,$ip" >> "$output_dir/ip_list.txt"
  done < "$output_dir/final_domains.txt"

  echo "[*] SSLScan finalizado!"
  sleep 2
  menu
}

gerar_csv() {
  echo "dominio,ip,tls_versions,ciphers" > "$output_dir/final_report.csv"

  while read -r line; do
    domain=$(echo "$line" | cut -d',' -f1)
    ip=$(echo "$line" | cut -d',' -f2)

    scan_file="$output_dir/${domain}_sslscan.txt"
    [ ! -f "$scan_file" ] && continue

    # Extrair versões TLS suportadas
    tls_versions=$(grep -E 'TLSv1\.|TLSv1\.1' "$scan_file" | grep -i accepted | awk '{print $2}' | sort -u | paste -sd ':' -)

    # Verificar cifras fracas
    weak_ciphers=$(grep -i -E 'weak|export|null' "$scan_file" | awk '{print $2}' | sort -u | paste -sd ':' -)

    [ -z "$tls_versions" ] && tls_versions="TLS OK"
    [ -z "$weak_ciphers" ] && weak_ciphers="None"

    echo "$domain,$ip,$tls_versions,$weak_ciphers" >> "$output_dir/final_report.csv"

  done < "$output_dir/ip_list.txt"

  echo "[*] Relatório CSV gerado: $output_dir/final_report.csv"
  sleep 2
  menu
}
menu
