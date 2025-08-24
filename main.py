"""

1.	Medir o tempo de verificação para 7 tamanhos diferentes de blocos (1KB a 100MB) : •	Seleção de tamanhos: 1KB, 10KB, 100KB, 1MB, 10MB, 50MB, 100MB   
2.	Calcular o throughput (MB/s) de cada algoritmo por faixa de tamanho
3. Protocolo de medição e repetições

4.	Identificar pontos de cruzamento onde um algoritmo supera o outro
5.	Desenvolver um modelo preditivo simples para estimar desempenho baseado no tamanho
6.	Criar um guia de decisão prático para desenvolvedores

"""

#!/usr/bin/env python3
"""
Análise do Impacto do Tamanho de Blocos de Dados no Desempenho 
da Verificação de Assinaturas Ed25519 versus RSA-2048

Autor: [Seu Nome]
Data: Agosto 2024
"""

import os
import time
import json
import statistics
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, padding
from cryptography.exceptions import InvalidSignature
from scipy import stats
from sklearn.linear_model import LinearRegression
import warnings
warnings.filterwarnings('ignore')

class VerificationBenchmark:
    """
    Classe para benchmark de verificação de assinaturas Ed25519 vs RSA-2048
    com diferentes tamanhos de blocos de dados.
    """
    
    def __init__(self):
        """Inicializa o benchmark com configurações padrão."""
        # Tamanhos de blocos para teste (em bytes)
        self.block_sizes = {
            '1KB': 1024,
            '10KB': 10240,
            '100KB': 102400,
            '1MB': 1048576,
            '10MB': 10485760,
            '50MB': 52428800,
            '100MB': 104857600
        }
        
        # Número de repetições para cada teste
        self.iterations = 100  # Ajustável conforme necessário
        
        # Resultados
        self.results = []
        
        # Preparar chaves
        print("Inicializando ambiente de teste...")
        self._prepare_keys()
        
    def _prepare_keys(self):
        """Gera as chaves para Ed25519 e RSA-2048."""
        print("Gerando chaves criptográficas...")
        
        # Ed25519
        self.ed25519_private = ed25519.Ed25519PrivateKey.generate()
        self.ed25519_public = self.ed25519_private.public_key()
        
        # RSA-2048
        self.rsa_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.rsa_public = self.rsa_private.public_key()
        
        print("✓ Chaves geradas com sucesso")
    
    def benchmark_verification(self, algorithm, data_size_bytes):
        """
        Realiza benchmark de verificação para um algoritmo e tamanho específicos.
        
        Args:
            algorithm: 'Ed25519' ou 'RSA-2048'
            data_size_bytes: Tamanho dos dados em bytes
            
        Returns:
            Dict com estatísticas do benchmark
        """
        # Gerar dados aleatórios
        data = os.urandom(data_size_bytes)
        
        # Criar assinatura
        if algorithm == 'Ed25519':
            signature = self.ed25519_private.sign(data)
            public_key = self.ed25519_public
        else:  # RSA-2048
            signature = self.rsa_private.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            public_key = self.rsa_public
        
        # Realizar múltiplas verificações e medir tempo
        times = []
        
        # Aquecimento (descartado)
        for _ in range(10):
            if algorithm == 'Ed25519':
                public_key.verify(signature, data)
            else:
                public_key.verify(
                    signature, data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
        
        # Medições reais
        for _ in range(self.iterations):
            start = time.perf_counter_ns()
            
            if algorithm == 'Ed25519':
                public_key.verify(signature, data)
            else:  # RSA-2048
                public_key.verify(
                    signature, data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            
            end = time.perf_counter_ns()
            times.append((end - start) / 1_000_000)  # Converter para ms
        
        # Calcular estatísticas
        return {
            'algorithm': algorithm,
            'data_size_bytes': data_size_bytes,
            'data_size_mb': data_size_bytes / (1024 * 1024),
            'mean_ms': statistics.mean(times),
            'median_ms': statistics.median(times),
            'stdev_ms': statistics.stdev(times),
            'min_ms': min(times),
            'max_ms': max(times),
            'p95_ms': np.percentile(times, 95),
            'p99_ms': np.percentile(times, 99),
            'throughput_mbps': (data_size_bytes / (1024 * 1024)) / (statistics.mean(times) / 1000),
            'all_times': times
        }
    
    def run_complete_benchmark(self):
        """Executa o benchmark completo para todos os tamanhos e algoritmos."""
        print("\n" + "="*60)
        print("INICIANDO BENCHMARK DE VERIFICAÇÃO")
        print("="*60)
        
        total_tests = len(self.block_sizes) * 2  # 2 algoritmos
        current_test = 0
        
        for size_label, size_bytes in self.block_sizes.items():
            print(f"\n→ Testando bloco de {size_label}...")
            
            # Ed25519
            current_test += 1
            print(f"  [{current_test}/{total_tests}] Ed25519... ", end='', flush=True)
            result_ed = self.benchmark_verification('Ed25519', size_bytes)
            result_ed['size_label'] = size_label
            self.results.append(result_ed)
            print(f"✓ {result_ed['mean_ms']:.3f}ms")
            
            # RSA-2048
            current_test += 1
            print(f"  [{current_test}/{total_tests}] RSA-2048... ", end='', flush=True)
            result_rsa = self.benchmark_verification('RSA-2048', size_bytes)
            result_rsa['size_label'] = size_label
            self.results.append(result_rsa)
            print(f"✓ {result_rsa['mean_ms']:.3f}ms")
            
            # Mostrar comparação imediata
            ratio = result_rsa['mean_ms'] / result_ed['mean_ms']
            print(f"  → RSA/Ed25519 ratio: {ratio:.2f}x")
        
        print("\n" + "="*60)
        print("BENCHMARK CONCLUÍDO")
        print("="*60)
    
    def analyze_results(self):
        """Analisa os resultados e identifica pontos importantes."""
        df = pd.DataFrame(self.results)
        
        print("\n" + "="*60)
        print("ANÁLISE DOS RESULTADOS")
        print("="*60)
        
        # Tabela comparativa
        pivot_table = df.pivot(index='size_label', columns='algorithm', values='mean_ms')
        pivot_table['Ratio (RSA/Ed)'] = pivot_table['RSA-2048'] / pivot_table['Ed25519']
        
        print("\n📊 Tempo Médio de Verificação (ms):")
        print("-" * 50)
        print(pivot_table.to_string(float_format='%.3f'))
        
        # Análise de throughput
        pivot_throughput = df.pivot(index='size_label', columns='algorithm', values='throughput_mbps')
        print("\n📈 Throughput (MB/s):")
        print("-" * 50)
        print(pivot_throughput.to_string(float_format='%.2f'))
        
        # Encontrar ponto de cruzamento (se existir)
        self._find_crossover_point(df)
        
        # Modelagem matemática
        self._create_predictive_model(df)
        
        return df
    
    def _find_crossover_point(self, df):
        """Identifica o ponto onde as curvas de desempenho se aproximam."""
        print("\n🎯 Análise de Convergência:")
        print("-" * 50)
        
        ed_data = df[df['algorithm'] == 'Ed25519'].sort_values('data_size_mb')
        rsa_data = df[df['algorithm'] == 'RSA-2048'].sort_values('data_size_mb')
        
        ratios = []
        for size in ed_data['data_size_mb'].values:
            ed_time = ed_data[ed_data['data_size_mb'] == size]['mean_ms'].values[0]
            rsa_time = rsa_data[rsa_data['data_size_mb'] == size]['mean_ms'].values[0]
            ratio = rsa_time / ed_time
            ratios.append((size, ratio))
            
        # Encontrar onde a razão é mínima
        min_ratio = min(ratios, key=lambda x: x[1])
        print(f"Menor diferença relativa: {min_ratio[1]:.2f}x em {min_ratio[0]:.1f}MB")
        
        # Verificar tendência
        if ratios[-1][1] < ratios[0][1]:
            print("Tendência: Convergência com aumento do tamanho dos dados")
        else:
            print("Tendência: Divergência com aumento do tamanho dos dados")
    
    def _create_predictive_model(self, df):
        """Cria modelos preditivos para cada algoritmo."""
        print("\n📐 Modelos Preditivos (T = a + b*S):")
        print("-" * 50)
        
        for algo in ['Ed25519', 'RSA-2048']:
            algo_data = df[df['algorithm'] == algo]
            X = algo_data['data_size_mb'].values.reshape(-1, 1)
            y = algo_data['mean_ms'].values
            
            model = LinearRegression()
            model.fit(X, y)
            
            r2 = model.score(X, y)
            
            print(f"\n{algo}:")
            print(f"  T = {model.intercept_:.3f} + {model.coef_[0]:.3f} × S")
            print(f"  R² = {r2:.4f}")
            
            # Predições para tamanhos intermediários
            test_sizes = [5, 25, 75]  # MB
            print(f"  Predições:")
            for size in test_sizes:
                pred = model.predict([[size]])[0]
                print(f"    {size}MB: {pred:.2f}ms")
    
    def generate_plots(self):
        """Gera gráficos para visualização dos resultados."""
        df = pd.DataFrame(self.results)
        
        # Configurar estilo
        plt.style.use('seaborn-v0_8-darkgrid')
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        # Gráfico 1: Tempo de execução vs Tamanho
        ax1 = axes[0, 0]
        for algo in ['Ed25519', 'RSA-2048']:
            algo_data = df[df['algorithm'] == algo].sort_values('data_size_mb')
            ax1.plot(algo_data['data_size_mb'], algo_data['mean_ms'], 
                    marker='o', linewidth=2, markersize=8, label=algo)
        ax1.set_xlabel('Tamanho do Bloco (MB)')
        ax1.set_ylabel('Tempo de Verificação (ms)')
        ax1.set_title('Tempo de Verificação vs Tamanho do Bloco')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        ax1.set_xscale('log')
        ax1.set_yscale('log')
        
        # Gráfico 2: Throughput
        ax2 = axes[0, 1]
        for algo in ['Ed25519', 'RSA-2048']:
            algo_data = df[df['algorithm'] == algo].sort_values('data_size_mb')
            ax2.plot(algo_data['data_size_mb'], algo_data['throughput_mbps'], 
                    marker='s', linewidth=2, markersize=8, label=algo)
        ax2.set_xlabel('Tamanho do Bloco (MB)')
        ax2.set_ylabel('Throughput (MB/s)')
        ax2.set_title('Throughput vs Tamanho do Bloco')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        ax2.set_xscale('log')
        
        # Gráfico 3: Razão RSA/Ed25519
        ax3 = axes[1, 0]
        ed_data = df[df['algorithm'] == 'Ed25519'].sort_values('data_size_mb')
        rsa_data = df[df['algorithm'] == 'RSA-2048'].sort_values('data_size_mb')
        
        ratios = []
        sizes = []
        for size in ed_data['data_size_mb'].values:
            ed_time = ed_data[ed_data['data_size_mb'] == size]['mean_ms'].values[0]
            rsa_time = rsa_data[rsa_data['data_size_mb'] == size]['mean_ms'].values[0]
            ratios.append(rsa_time / ed_time)
            sizes.append(size)
        
        ax3.plot(sizes, ratios, marker='D', linewidth=2, markersize=8, color='red')
        ax3.axhline(y=1, color='gray', linestyle='--', alpha=0.5)
        ax3.set_xlabel('Tamanho do Bloco (MB)')
        ax3.set_ylabel('Razão RSA/Ed25519')
        ax3.set_title('Vantagem Relativa do Ed25519')
        ax3.grid(True, alpha=0.3)
        ax3.set_xscale('log')
        
        # Gráfico 4: Box plot comparativo
        ax4 = axes[1, 1]
        data_for_box = []
        labels_for_box = []
        
        for size_label in ['1KB', '100KB', '10MB', '100MB']:
            for algo in ['Ed25519', 'RSA-2048']:
                result = next((r for r in self.results 
                             if r['size_label'] == size_label and r['algorithm'] == algo), None)
                if result:
                    data_for_box.append(result['all_times'])
                    labels_for_box.append(f"{algo}\n{size_label}")
        
        bp = ax4.boxplot(data_for_box, labels=labels_for_box, patch_artist=True)
        colors = ['lightblue', 'lightcoral'] * 4
        for patch, color in zip(bp['boxes'], colors):
            patch.set_facecolor(color)
        
        ax4.set_ylabel('Tempo de Verificação (ms)')
        ax4.set_title('Distribuição dos Tempos de Verificação')
        ax4.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        
        # Salvar figura
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"benchmark_results_{timestamp}.png"
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"\n📊 Gráficos salvos em: {filename}")
        
        plt.show()
    
    def export_results(self, format='all'):
        """
        Exporta os resultados para diferentes formatos.
        
        Args:
            format: 'csv', 'json', 'excel' ou 'all'
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        df = pd.DataFrame(self.results)
        
        # Remover a coluna 'all_times' para exportação
        df_export = df.drop('all_times', axis=1)
        
        if format in ['csv', 'all']:
            filename = f"results_{timestamp}.csv"
            df_export.to_csv(filename, index=False)
            print(f"✓ Resultados exportados para {filename}")
        
        if format in ['json', 'all']:
            filename = f"results_{timestamp}.json"
            df_export.to_json(filename, orient='records', indent=2)
            print(f"✓ Resultados exportados para {filename}")
        
        if format in ['excel', 'all']:
            filename = f"results_{timestamp}.xlsx"
            with pd.ExcelWriter(filename, engine='openpyxl') as writer:
                # Dados detalhados
                df_export.to_excel(writer, sheet_name='Dados Completos', index=False)
                
                # Tabela resumo
                pivot = df.pivot(index='size_label', columns='algorithm', values='mean_ms')
                pivot['Ratio'] = pivot['RSA-2048'] / pivot['Ed25519']
                pivot.to_excel(writer, sheet_name='Resumo')
                
                # Estatísticas
                stats_df = df.groupby('algorithm')[['mean_ms', 'throughput_mbps']].agg(['mean', 'min', 'max'])
                stats_df.to_excel(writer, sheet_name='Estatísticas')
            
            print(f"✓ Resultados exportados para {filename}")
    
    def generate_report(self):
        """Gera um relatório em texto dos resultados."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        df = pd.DataFrame(self.results)
        
        report = []
        report.append("="*70)
        report.append("RELATÓRIO DE BENCHMARK DE VERIFICAÇÃO DE ASSINATURAS")
        report.append("="*70)
        report.append(f"Data de Execução: {timestamp}")
        report.append(f"Algoritmos Testados: Ed25519, RSA-2048")
        report.append(f"Tamanhos de Bloco: {', '.join(self.block_sizes.keys())}")
        report.append(f"Iterações por Teste: {self.iterations}")
        report.append("")
        
        # Resultados principais
        report.append("RESULTADOS PRINCIPAIS")
        report.append("-"*70)
        
        pivot = df.pivot(index='size_label', columns='algorithm', values='mean_ms')
        pivot['Ratio'] = pivot['RSA-2048'] / pivot['Ed25519']
        
        report.append("\nTempo Médio de Verificação (ms):")
        report.append(pivot.to_string(float_format='%.3f'))
        
        # Análise de desempenho
        report.append("\n\nANÁLISE DE DESEMPENHO")
        report.append("-"*70)
        
        # Melhor e pior caso para cada algoritmo
        for algo in ['Ed25519', 'RSA-2048']:
            algo_data = df[df['algorithm'] == algo]
            best = algo_data.loc[algo_data['mean_ms'].idxmin()]
            worst = algo_data.loc[algo_data['mean_ms'].idxmax()]
            
            report.append(f"\n{algo}:")
            report.append(f"  Melhor caso: {best['size_label']} - {best['mean_ms']:.3f}ms")
            report.append(f"  Pior caso: {worst['size_label']} - {worst['mean_ms']:.3f}ms")
            report.append(f"  Throughput médio: {algo_data['throughput_mbps'].mean():.2f} MB/s")
        
        # Recomendações
        report.append("\n\nRECOMENDAÇÕES")
        report.append("-"*70)
        
        # Análise por faixa de tamanho
        small_data = df[df['data_size_mb'] < 1]
        medium_data = df[(df['data_size_mb'] >= 1) & (df['data_size_mb'] <= 10)]
        large_data = df[df['data_size_mb'] > 10]
        
        for category, data, label in [(small_data, "Dados Pequenos (<1MB)"),
                                       (medium_data, "Dados Médios (1-10MB)"),
                                       (large_data, "Dados Grandes (>10MB)")]:
            if not data.empty:
                ed_mean = data[data['algorithm'] == 'Ed25519']['mean_ms'].mean()
                rsa_mean = data[data['algorithm'] == 'RSA-2048']['mean_ms'].mean()
                ratio = rsa_mean / ed_mean
                
                report.append(f"\n{label}:")
                report.append(f"  Vantagem do Ed25519: {ratio:.2f}x")
                
                if ratio > 5:
                    report.append("  Recomendação: Ed25519 FORTEMENTE recomendado")
                elif ratio > 2:
                    report.append("  Recomendação: Ed25519 recomendado")
                else:
                    report.append("  Recomendação: Escolha baseada em outros fatores")
        
        # Salvar relatório
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))
        
        print(f"\n📄 Relatório salvo em: {filename}")
        
        # Também imprimir na tela
        print('\n'.join(report))


def main():
    """Função principal para executar o benchmark."""
    print("\n" + "="*70)
    print(" BENCHMARK DE VERIFICAÇÃO DE ASSINATURAS DIGITAIS")
    print(" Ed25519 vs RSA-2048: Análise por Tamanho de Bloco")
    print("="*70)
    
    # Criar e executar benchmark
    benchmark = VerificationBenchmark()
    
    # Executar testes
    start_time = time.time()
    benchmark.run_complete_benchmark()
    elapsed = time.time() - start_time
    
    print(f"\n⏱️  Tempo total de execução: {elapsed:.2f} segundos")
    
    # Analisar resultados
    df_results = benchmark.analyze_results()
    
    # Gerar visualizações
    benchmark.generate_plots()
    
    # Exportar resultados
    benchmark.export_results('all')
    
    # Gerar relatório
    benchmark.generate_report()
    
    print("\n✅ Benchmark concluído com sucesso!")
    print("📁 Verifique os arquivos gerados no diretório atual.")


if __name__ == "__main__":
    main()