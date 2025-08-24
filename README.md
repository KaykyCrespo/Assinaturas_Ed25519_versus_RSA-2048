# Assinaturas_Ed25519_versus_RSA-2048
Análise do Impacto do Tamanho de Blocos de Dados no Desempenho da Verificação de Assinaturas Ed25519 versus RSA-2048 para apresentação no Congresso CONIC - SEMESP


1. Instalação das Dependências:
pip install cryptography pandas numpy matplotlib seaborn scipy scikit-learn openpyxl


🔐 Benchmark Criptográfico: Ed25519 vs RSA-2048

Este projeto implementa um benchmark comparativo entre os algoritmos de assinatura digital Ed25519 e RSA-2048, analisando o impacto do tamanho dos blocos de dados no desempenho da verificação de assinaturas.

Foram realizados testes com diferentes tamanhos de dados (de 1KB até 100MB), medindo tempo de execução, variabilidade, throughput e escalabilidade. O código também gera relatórios, tabelas, gráficos e exportações em diversos formatos.

📋 Funcionalidades

Benchmark de verificação de assinaturas Ed25519 e RSA-2048.

Testes com múltiplos tamanhos de blocos de dados.

Cálculo de métricas estatísticas: média, mediana, desvio padrão, percentis, throughput.

Análise de convergência/divergência entre os algoritmos.

Modelos preditivos lineares (regressão) para estimar desempenho em novos cenários.

Geração de gráficos comparativos.

Exportação de resultados em CSV, JSON e Excel formatado.

Relatório textual detalhado.

🛠️ Tecnologias Utilizadas

Python 3.10+

cryptography
 → geração e verificação de chaves/assinaturas.

NumPy
 e Pandas
 → análise de dados.

Matplotlib
 e Seaborn
 → visualização gráfica.

SciPy
 e scikit-learn
 → análise estatística e modelagem preditiva.

openpyxl
 → exportação em Excel com formatação avançada.

🚀 Como Executar
1. Clone o repositório
git clone https://github.com/seu-usuario/benchmark-ed25519-rsa.git
cd benchmark-ed25519-rsa

2. Crie e ative um ambiente virtual (opcional, mas recomendado)
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

3. Instale as dependências
pip install -r requirements.txt

4. Execute o benchmark
python benchmark.py

📊 Saídas

Terminal → Logs de execução, tempo médio e razão RSA/Ed25519.

Gráficos → Arquivo .png com visualizações comparativas.

Exportações:

results_YYYYMMDD_HHMMSS.csv

results_YYYYMMDD_HHMMSS.json

Resultados_Ed25519_vs_RSA2048_YYYYMMDD_HHMMSS.xlsx (com planilhas formatadas).

Relatório textual → Consolida principais métricas.

📂 Estrutura do Projeto
benchmark-ed25519-rsa/
├── benchmark.py         # Script principal com a classe VerificationBenchmark
├── requirements.txt     # Dependências do projeto
├── README.md            # Documentação
├── results/             # (gerado) CSV, JSON e Excel de resultados
├── plots/               # (gerado) gráficos PNG

📈 Exemplo de Resultados

Ed25519 apresenta desempenho consistentemente superior ao RSA-2048 em todos os tamanhos de blocos testados.

A diferença tende a aumentar com blocos maiores, indicando maior escalabilidade do Ed25519.

O throughput do RSA permanece significativamente menor, mesmo com ajustes de tamanho de dados.

📜 Licença

Este projeto está sob a licença MIT.