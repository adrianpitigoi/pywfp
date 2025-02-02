"""
A recursive-descent parser for a Windivert-style filter language.
Supports operators: and, or, not, parentheses.
Only conjunctions (AND) are allowed for conversion to WFP filters.
Added support for IP ranges using hyphen notation (e.g., 192.168.1.1-192.168.1.255)
"""

import re
from dataclasses import dataclass
from typing import List, Union, Optional
import logging

# Token types
TOKEN_AND = "AND"
TOKEN_OR = "OR"
TOKEN_NOT = "NOT"
TOKEN_LPAREN = "LPAREN"
TOKEN_RPAREN = "RPAREN"
TOKEN_OPERATOR = "OPERATOR"
TOKEN_IDENTIFIER = "IDENTIFIER"
TOKEN_NUMBER = "NUMBER"
TOKEN_RANGE = "RANGE"
TOKEN_EOF = "EOF"

logger = logging.getLogger(__name__)


@dataclass
class Token:
    type: str
    value: str


class Lexer:
    token_specification = [
        ("AND", r"\band\b"),
        ("OR", r"\bor\b"),
        ("NOT", r"\bnot\b"),
        ("OPERATOR", r"==|="),
        ("LPAREN", r"\("),
        ("RPAREN", r"\)"),
        # Updated NUMBER pattern to handle IP ranges
        ("RANGE", r"(?:\d{1,3}\.){3}\d{1,3}-(?:\d{1,3}\.){3}\d{1,3}"),
        ("NUMBER", r"(?:\d{1,3}\.){3}\d{1,3}|0x[0-9A-Fa-f]+|\d+"),
        ("IDENTIFIER", r"\b(?:inbound|outbound|action|[A-Za-z][A-Za-z0-9_.\[\]]*)\b"),
        ("SKIP", r"[ \t]+"),
        ("MISMATCH", r"."),
    ]

    def __init__(self, text: str):
        logger.debug("Initializing lexer")
        self.text = text
        self.tokens = self.tokenize(text)
        self.pos = 0

    def tokenize(self, text: str) -> List[Token]:
        logger.debug("Starting tokenization")
        tok_regex = "|".join("(?P<%s>%s)" % pair for pair in self.token_specification)
        tokens = []
        line_start = 0
        for mo in re.finditer(tok_regex, text):
            kind = mo.lastgroup
            value = mo.group()

            # Check for any skipped text between matches
            if mo.start() > line_start:
                skipped_text = text[line_start : mo.start()].strip()
                if skipped_text:  # If there's non-whitespace text that was skipped
                    raise ValueError(f"Invalid syntax: Unexpected text '{skipped_text}'")

            line_start = mo.end()

            if kind == "RANGE":
                tokens.append(Token(TOKEN_RANGE, value))
            elif kind == "NUMBER":
                tokens.append(Token(TOKEN_NUMBER, value))
            elif kind == "IDENTIFIER":
                tokens.append(Token(TOKEN_IDENTIFIER, value))
            elif kind == "AND":
                tokens.append(Token(TOKEN_AND, value))
            elif kind == "OR":
                tokens.append(Token(TOKEN_OR, value))
            elif kind == "NOT":
                tokens.append(Token(TOKEN_NOT, value))
            elif kind == "OPERATOR":
                tokens.append(Token(TOKEN_OPERATOR, value))
            elif kind == "LPAREN":
                tokens.append(Token(TOKEN_LPAREN, value))
            elif kind == "RPAREN":
                tokens.append(Token(TOKEN_RPAREN, value))
            elif kind == "SKIP":
                continue
            elif kind == "MISMATCH":
                raise ValueError(f"Unexpected character: {value}")

        # Check if there's any remaining text after the last match
        if line_start < len(text):
            remaining_text = text[line_start:].strip()
            if remaining_text:
                raise ValueError(f"Invalid syntax: Unexpected text '{remaining_text}'")

        tokens.append(Token(TOKEN_EOF, ""))
        logger.debug(f"Tokenization complete: {len(tokens)} tokens found")
        return tokens

    def next_token(self) -> Token:
        if self.pos < len(self.tokens):
            tok = self.tokens[self.pos]
            self.pos += 1
            return tok
        return Token(TOKEN_EOF, "")

    def peek(self) -> Token:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return Token(TOKEN_EOF, "")


# AST node definitions
@dataclass
class ASTNode:
    pass


@dataclass
class ConditionNode(ASTNode):
    field: str
    operator: Union[str, None]
    value: Union[str, None]


@dataclass
class AndNode(ASTNode):
    left: ASTNode
    right: ASTNode


@dataclass
class OrNode(ASTNode):
    left: ASTNode
    right: ASTNode


@dataclass
class NotNode(ASTNode):
    child: ASTNode


class Parser:
    def __init__(self, lexer: Lexer):
        logger.debug("Initializing parser")
        self.lexer = lexer
        self.current_token = self.lexer.next_token()

    def eat(self, token_type: str):
        if self.current_token.type == token_type:
            self.current_token = self.lexer.next_token()
        else:
            raise ValueError(f"Expected token {token_type}, got {self.current_token.type}")

    def parse(self) -> ASTNode:
        logger.info("Starting parse")
        result = self.expression()
        if self.current_token.type != TOKEN_EOF:
            raise ValueError(f"Unexpected token after valid expression: {self.current_token.value}")
        logger.debug("Parse complete")
        return result

    def expression(self) -> ASTNode:
        node = self.term()
        while self.current_token.type == TOKEN_OR:
            self.eat(TOKEN_OR)
            node = OrNode(left=node, right=self.term())
        return node

    def term(self) -> ASTNode:
        node = self.factor()
        while self.current_token.type == TOKEN_AND:
            self.eat(TOKEN_AND)
            node = AndNode(left=node, right=self.factor())
        return node

    def factor(self) -> ASTNode:
        if self.current_token.type == TOKEN_NOT:
            self.eat(TOKEN_NOT)
            return NotNode(child=self.factor())
        elif self.current_token.type == TOKEN_LPAREN:
            self.eat(TOKEN_LPAREN)
            node = self.expression()
            self.eat(TOKEN_RPAREN)
            return node
        else:
            return self.condition()

    def condition(self) -> ASTNode:
        if self.current_token.type != TOKEN_IDENTIFIER:
            raise ValueError("Expected identifier in condition")
        field = self.current_token.value
        self.eat(TOKEN_IDENTIFIER)
        if self.current_token.type == TOKEN_OPERATOR:
            operator = self.current_token.value
            self.eat(TOKEN_OPERATOR)
            if self.current_token.type in (TOKEN_IDENTIFIER, TOKEN_NUMBER, TOKEN_RANGE):
                value = self.current_token.value
                self.eat(self.current_token.type)
            else:
                raise ValueError("Expected identifier, number, or range after operator")
            return ConditionNode(field=field, operator=operator, value=value)
        else:
            # Bare flag condition (implicit: field != 0)
            return ConditionNode(field=field, operator=None, value=None)


class FilterExpression:
    def __init__(self, ast: ASTNode):
        self.ast = ast

    def flatten(self) -> List[ConditionNode]:
        """
        Flatten the AST if it is a pure conjunction (AND) of conditions.
        Raises an error if OR or NOT are encountered.
        """

        def _flatten(node: ASTNode) -> List[ConditionNode]:
            if isinstance(node, ConditionNode):
                return [node]
            elif isinstance(node, AndNode):
                return _flatten(node.left) + _flatten(node.right)
            else:
                raise ValueError("Only conjunctions (AND) of conditions are supported for WFP mapping")

        return _flatten(self.ast)


class FilterCondition:
    """Represents a single condition in a filter expression."""

    def __init__(self, field: str, operator: Optional[str], value: Optional[str]):
        self.field = field
        self.operator = operator
        self.value = value

    def __str__(self) -> str:
        if self.operator is None and self.value is None:
            return f"{self.field}"
        return f"{self.field} {self.operator} {self.value}"

    def __repr__(self) -> str:
        return f"FilterCondition(field='{self.field}', operator='{self.operator}', value='{self.value}')"


class FilterParser:
    @staticmethod
    def parse(filter_str: str) -> FilterExpression:
        logger.info(f"Parsing filter string: {filter_str}")
        lexer = Lexer(filter_str)
        parser = Parser(lexer)
        ast = parser.parse()
        logger.info("Filter parsed successfully")
        return FilterExpression(ast)

    def parse_condition(self) -> FilterCondition:
        """Parse a single condition."""
        token = self.current_token

        # Parse field
        if token.type != TOKEN_IDENTIFIER:
            raise ValueError(f"Expected identifier, got {token.type}")
        field = token.value
        self.advance()

        # Handle conditions with operators
        if self.current_token.type == TOKEN_OPERATOR:
            operator = self.current_token.value
            self.advance()

            # Parse value
            if self.current_token.type not in [TOKEN_IDENTIFIER, TOKEN_NUMBER, TOKEN_RANGE]:
                raise ValueError(f"Expected value, got {self.current_token.type}")
            value = self.current_token.value
            self.advance()

            return FilterCondition(field, operator, value)

        # For conditions without operators (like 'outbound', 'tcp')
        return FilterCondition(field, None, None)

    def parse_expression(self) -> FilterExpression:
        """Parse a complete expression."""
        conditions = []
        conditions.append(self.parse_condition())

        while self.current_token.type != TOKEN_EOF:
            # Require AND between conditions
            if self.current_token.type != TOKEN_AND:
                raise ValueError(f"Expected 'and' between conditions, got '{self.current_token.value}'")
            self.advance()

            conditions.append(self.parse_condition())

        return FilterExpression(conditions)
