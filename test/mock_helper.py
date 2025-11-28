from html.parser import HTMLParser
from types import SimpleNamespace
from typing import  Optional, Type, TypeVar, ClassVar, Any


# 모의 클래스 프로토타입 정의
# MockClassPrototype = interfaces.py에 정의된 클래스를 흉내내기 위한 제네릭 클래스

V = ClassVar[dict]

class MockClassPrototype:
    def __init__(self, init_param: Any | None = None,):
        self.init_param = init_param or SimpleNamespace().__dict__
        
        for key, value in self.init_param.items():
            self.__setattr__(key, value)

    def __repr__(self):
        return f"MockClassPrototype({self.__dict__} / )"

T = TypeVar("T")


def to_mock_interface(obj: Optional[T], class_type: Type[T]) -> T:
    """interfaces.py 인스턴스 생성 함수
    
    Args:
        obj (Any): 클래스 인스턴스에 넣을 값
        class_type (Type[T]): interfaces.py에 정의된 클래스 타입

    Raises:
        TypeError: _description_
        TypeError: _description_

    Returns:
        T: obj로 class_type에 해당하는 인스턴스를 반환함
    """
    # 이미 올바른 타입의 인스턴스인지 확인합니다.
    # class_type은 런타임에 사용 가능한 실제 클래스이므로 isinstance 사용이 가능합니다.
    if isinstance(obj, class_type):
        return obj

    # 딕셔너리에서 변환
    if isinstance(obj, dict):
        # class_type.__init__.__annotations__.keys() 등을 사용해 허용된 키를 가져올 수 있습니다.
        # 여기서는 간단히 __init__ 메서드의 인자 이름을 사용합니다.
        allowed = list(class_type.__init__.__annotations__.keys())
        # self와 return 어노테이션은 제외
        allowed = [k for k in allowed if k not in ['self', 'return']]
        
        kwargs = {k: v for k, v in obj.items() if k in allowed}
        return class_type(**kwargs) # 실제 클래스 타입으로 인스턴스화합니다.

    # MockScannerConfig-like object에서 변환 (속성 매핑)
    if isinstance(obj, type) or not hasattr(obj, '__dict__'): # obj 인자의 type 체크 또는 일반 객체 체크
         raise TypeError(f"Cannot convert object of type {type(obj)!r} to {class_type.__name__}")

    #  객체의 속성에서 값을 추출하여 인스턴스 생성
    attrs = {k: getattr(obj, k) for k in dir(obj)
                if not k.startswith('_') and not callable(getattr(obj, k))}
    if attrs:
        allowed = list(class_type.__init__.__annotations__.keys())
        allowed = [k for k in allowed if k not in ['self', 'return']]
        kwargs = {k: v for k, v in attrs.items() if k in allowed}
        return class_type(**kwargs)

    raise TypeError(f"Cannot convert object of type {type(obj)!r} to {class_type.__name__}")


"========== Common Util Class========="

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.current_input = None

    def handle_starttag(self, tag, attrs):
        if tag == 'form':
            self.current_form = {'inputs': []}
            self.forms.append(self.current_form)
        elif tag == 'input':
            self.current_input = {'name': attrs.get('name'), 'value': attrs.get('value')}
            self.current_form['inputs'].append(self.current_input)

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current_form = None
        elif tag == 'input':
            self.current_input = None