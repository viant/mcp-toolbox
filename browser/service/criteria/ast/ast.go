package ast

type Qualify struct {
	X Node
}

type Group struct {
	X Node
}

type Binary struct {
	X  Node
	Op string
	Y  Node
}

type Unary struct {
	Op string
	X  Node
}

type Selector struct {
	X string
}

type Literal struct {
	Value string
	Type  string
	Quote string
}
