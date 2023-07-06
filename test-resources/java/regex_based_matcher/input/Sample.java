package com.uber.piranha;

import java.util.List;

class A {

    void foobar() {
        boolean b = foo().bar().baz();
        if (b) {
            System.out.println("Hello World!");
        }
        System.out.println(b);
    }

    @DoNotCleanup
    void barfn() {
        boolean b = foo().bar().baz();
        System.out.println(b);
    }

    void foofn() {
        int total = abc().def().ghi();
    }

    void someTypeChange() {
        // Will get updated
        List<Integer> a = getList();
        Integer item = getItem();
        a.add(item);
        
        // Will not get updated
        List<String> b = getListStr();
        Integer item = getItemStr();
        b.add(item);
    }

}