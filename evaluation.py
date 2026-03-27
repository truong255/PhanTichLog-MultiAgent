"""
Evaluation Script - Calculate Precision, Recall, F1-Score
Compares predicted threats vs ground truth labels

Usage:
python evaluation.py --predictions results.json --ground_truth labels.json
"""

import json
import argparse
from typing import Dict, List, Tuple
from collections import defaultdict


class ThreatEvaluator:
    """Evaluate threat detection performance"""
    
    def __init__(self, predictions: List[Dict], ground_truth: List[Dict]):
        """
        predictions: List of threat analysis results
        ground_truth: List of labeled logs with actual threat type
        """
        self.predictions = predictions
        self.ground_truth = ground_truth
        self.metrics = {}
    
    def evaluate(self) -> Dict:
        """Calculate all metrics"""
        
        # Match predictions with ground truth
        results = self._match_predictions()
        
        # Calculate overall metrics
        overall = self._calculate_metrics(results['all'])
        self.metrics['overall'] = overall
        
        # Calculate per-attack-type metrics
        self.metrics['per_attack'] = {}
        for attack_type in results['by_type']:
            self.metrics['per_attack'][attack_type] = self._calculate_metrics(results['by_type'][attack_type])
        
        # Calculate confusion matrix
        self.metrics['confusion_matrix'] = self._build_confusion_matrix()
        
        return self.metrics
    
    def _match_predictions(self) -> Dict:
        """Match predictions with ground truth by request"""
        
        results = {
            'all': {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0},
            'by_type': defaultdict(lambda: {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0})
        }
        
        # Create mapping of ground truth by IP/timestamp
        gt_map = {}
        for gt in self.ground_truth:
            key = (gt.get('ip'), gt.get('timestamp'))
            gt_map[key] = gt.get('attack_type', 'None')
        
        # Compare each prediction
        for pred in self.predictions:
            key = (pred.get('ip'), pred.get('timestamp'))
            true_label = gt_map.get(key, 'None')
            pred_label = pred.get('attack_type', 'None')
            
            # Classify as TP/FP/TN/FN
            is_positive_true = true_label != 'None'
            is_positive_pred = pred_label != 'None'
            
            if is_positive_true and is_positive_pred:
                if true_label == pred_label:
                    classification = 'tp'  # Correct detection
                else:
                    classification = 'fp'  # Wrong attack type
            elif is_positive_true and not is_positive_pred:
                classification = 'fn'  # Missed attack
            elif not is_positive_true and is_positive_pred:
                classification = 'fp'  # False alarm
            else:
                classification = 'tn'  # Correct negative
            
            results['all'][classification] += 1
            results['by_type'][true_label if is_positive_true else pred_label][classification] += 1
        
        return results
    
    def _calculate_metrics(self, counts: Dict) -> Dict:
        """Calculate Precision, Recall, F1-Score"""
        
        tp = counts['tp']
        fp = counts['fp']
        tn = counts['tn']
        fn = counts['fn']
        
        # Precision = TP / (TP + FP)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        
        # Recall = TP / (TP + FN)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        # F1-Score = 2 * (Precision * Recall) / (Precision + Recall)
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # Accuracy = (TP + TN) / Total
        total = tp + fp + tn + fn
        accuracy = (tp + tn) / total if total > 0 else 0
        
        # False Positive Rate = FP / (FP + TN)
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        return {
            'tp': tp,
            'fp': fp,
            'tn': tn,
            'fn': fn,
            'precision': round(precision * 100, 2),
            'recall': round(recall * 100, 2),
            'f1_score': round(f1, 4),
            'accuracy': round(accuracy * 100, 2),
            'false_positive_rate': round(fp_rate * 100, 2)
        }
    
    def _build_confusion_matrix(self) -> Dict:
        """Build confusion matrix by attack type"""
        
        attack_types = set()
        for pred in self.predictions:
            attack_types.add(pred.get('attack_type', 'None'))
        for gt in self.ground_truth:
            attack_types.add(gt.get('attack_type', 'None'))
        
        attack_types = sorted(list(attack_types))
        
        # Initialize matrix
        matrix = {t: {at: 0 for at in attack_types} for t in attack_types}
        
        # Build mapping
        gt_map = {}
        for gt in self.ground_truth:
            key = (gt.get('ip'), gt.get('timestamp'))
            gt_map[key] = gt.get('attack_type', 'None')
        
        # Fill matrix
        for pred in self.predictions:
            key = (pred.get('ip'), pred.get('timestamp'))
            true_label = gt_map.get(key, 'None')
            pred_label = pred.get('attack_type', 'None')
            matrix[true_label][pred_label] += 1
        
        return {
            'attack_types': attack_types,
            'matrix': matrix
        }
    
    def print_report(self):
        """Print formatted evaluation report"""
        
        print("\n" + "="*80)
        print("  THREAT DETECTION EVALUATION REPORT")
        print("="*80)
        
        # Overall metrics
        print("\n[OVERALL METRICS]")
        overall = self.metrics.get('overall', {})
        print(f"  Precision:           {overall.get('precision', 0)}%")
        print(f"  Recall:              {overall.get('recall', 0)}%")
        print(f"  F1-Score:            {overall.get('f1_score', 0)}")
        print(f"  Accuracy:            {overall.get('accuracy', 0)}%")
        print(f"  False Positive Rate: {overall.get('false_positive_rate', 0)}%")
        
        print(f"\n  Confusion:")
        print(f"    TP (True Positive):   {overall.get('tp', 0)}")
        print(f"    FP (False Positive):  {overall.get('fp', 0)}")
        print(f"    TN (True Negative):   {overall.get('tn', 0)}")
        print(f"    FN (False Negative):  {overall.get('fn', 0)}")
        
        # Per-attack-type metrics
        print("\n[PER-ATTACK-TYPE METRICS]")
        for attack_type, metrics in self.metrics.get('per_attack', {}).items():
            print(f"\n  {attack_type}:")
            print(f"    Precision: {metrics.get('precision', 0)}%")
            print(f"    Recall:    {metrics.get('recall', 0)}%")
            print(f"    F1-Score:  {metrics.get('f1_score', 0)}")
            print(f"    TP/FP/FN:  {metrics.get('tp', 0)}/{metrics.get('fp', 0)}/{metrics.get('fn', 0)}")
        
        # Confusion matrix
        cm = self.metrics.get('confusion_matrix', {})
        if cm.get('matrix'):
            print("\n[CONFUSION MATRIX]")
            attack_types = cm.get('attack_types', [])
            matrix = cm.get('matrix', {})
            
            # Print header
            print("  Predicted \\")
            print("   Actual  ", end="")
            for at in attack_types:
                print(f"{at[:8]:<10}", end="")
            print()
            
            # Print rows
            for true_type in attack_types:
                print(f"  {true_type[:8]:<8} ", end="")
                for pred_type in attack_types:
                    count = matrix.get(true_type, {}).get(pred_type, 0)
                    print(f"{count:<10}", end="")
                print()
        
        print("\n" + "="*80 + "\n")


def main():
    parser = argparse.ArgumentParser(description='Evaluate threat detection performance')
    parser.add_argument('--predictions', required=True, help='Path to predictions JSON file')
    parser.add_argument('--ground_truth', required=True, help='Path to ground truth labels JSON file')
    parser.add_argument('--output', help='Output report file (optional)')
    
    args = parser.parse_args()
    
    # Load files
    print("[...] Loading predictions and ground truth...")
    with open(args.predictions, 'r') as f:
        predictions = json.load(f)
    
    with open(args.ground_truth, 'r') as f:
        ground_truth = json.load(f)
    
    # Evaluate
    print(f"[...] Evaluating {len(predictions)} predictions against {len(ground_truth)} labels...")
    evaluator = ThreatEvaluator(predictions, ground_truth)
    metrics = evaluator.evaluate()
    
    # Print report
    evaluator.print_report()
    
    # Save report if requested
    if args.output:
        print(f"[OK] Saving detailed report to: {args.output}")
        with open(args.output, 'w') as f:
            json.dump(metrics, f, indent=2)


if __name__ == '__main__':
    main()
