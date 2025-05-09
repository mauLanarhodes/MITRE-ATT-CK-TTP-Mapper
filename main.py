# Entry point
from mapping_engine import map_iocs
from utils import load_iocs, write_csv

if __name__ == '__main__':
    iocs = load_iocs('samples/sample_input.txt')
    results = map_iocs(iocs)
    write_csv(results, 'output/report.csv')
    print("Mapping complete. Report saved to output/report.csv")
