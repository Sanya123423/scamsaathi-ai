"""
ScamSaathi - Machine Learning Package
"""

from .classifier import load_classifier, predict_message
from .dataset import get_labeled_examples

__all__ = ['load_classifier', 'predict_message', 'get_labeled_examples']
