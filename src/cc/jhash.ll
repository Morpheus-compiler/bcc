; ModuleID = 'jhash.bc'
source_filename = "/home/sebastiano/dev/linux/samples/bpf/jhash.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@rsp = common dso_local local_unnamed_addr global i64 0, align 8
@llvm.used = appending global [1 x i8*] [i8* bitcast (i32 (i8*, i32, i32)* @jhash to i8*)], section "llvm.metadata"

; Function Attrs: inlinehint norecurse nounwind readonly uwtable
define internal i32 @jhash(i8* nocapture readonly, i32, i32) #0 {
  %4 = add i32 %1, -559038737
  %5 = add i32 %4, %2
  %6 = icmp ugt i32 %1, 12
  br i1 %6, label %7, label %63

; <label>:7:                                      ; preds = %3, %7
  %8 = phi i8* [ %61, %7 ], [ %0, %3 ]
  %9 = phi i32 [ %58, %7 ], [ %5, %3 ]
  %10 = phi i32 [ %59, %7 ], [ %5, %3 ]
  %11 = phi i32 [ %53, %7 ], [ %5, %3 ]
  %12 = phi i32 [ %60, %7 ], [ %1, %3 ]
  %13 = bitcast i8* %8 to i32*
  %14 = load i32, i32* %13, align 1, !tbaa !2
  %15 = add i32 %14, %11
  %16 = getelementptr inbounds i8, i8* %8, i64 4
  %17 = bitcast i8* %16 to i32*
  %18 = load i32, i32* %17, align 1, !tbaa !2
  %19 = add i32 %18, %10
  %20 = getelementptr inbounds i8, i8* %8, i64 8
  %21 = bitcast i8* %20 to i32*
  %22 = load i32, i32* %21, align 1, !tbaa !2
  %23 = add i32 %22, %9
  %24 = sub i32 %15, %23
  %25 = shl i32 %23, 4
  %26 = lshr i32 %23, 28
  %27 = or i32 %26, %25
  %28 = xor i32 %27, %24
  %29 = add i32 %23, %19
  %30 = sub i32 %19, %28
  %31 = shl i32 %28, 6
  %32 = lshr i32 %28, 26
  %33 = or i32 %32, %31
  %34 = xor i32 %33, %30
  %35 = add i32 %28, %29
  %36 = sub i32 %29, %34
  %37 = shl i32 %34, 8
  %38 = lshr i32 %34, 24
  %39 = or i32 %38, %37
  %40 = xor i32 %39, %36
  %41 = add i32 %34, %35
  %42 = sub i32 %35, %40
  %43 = shl i32 %40, 16
  %44 = lshr i32 %40, 16
  %45 = or i32 %44, %43
  %46 = xor i32 %45, %42
  %47 = add i32 %40, %41
  %48 = sub i32 %41, %46
  %49 = shl i32 %46, 19
  %50 = lshr i32 %46, 13
  %51 = or i32 %50, %49
  %52 = xor i32 %51, %48
  %53 = add i32 %46, %47
  %54 = sub i32 %47, %52
  %55 = shl i32 %52, 4
  %56 = lshr i32 %52, 28
  %57 = or i32 %56, %55
  %58 = xor i32 %57, %54
  %59 = add i32 %52, %53
  %60 = add i32 %12, -12
  %61 = getelementptr inbounds i8, i8* %8, i64 12
  %62 = icmp ugt i32 %60, 12
  br i1 %62, label %7, label %63

; <label>:63:                                     ; preds = %7, %3
  %64 = phi i32 [ %1, %3 ], [ %60, %7 ]
  %65 = phi i32 [ %5, %3 ], [ %53, %7 ]
  %66 = phi i32 [ %5, %3 ], [ %59, %7 ]
  %67 = phi i32 [ %5, %3 ], [ %58, %7 ]
  %68 = phi i8* [ %0, %3 ], [ %61, %7 ]
  switch i32 %64, label %193 [
    i32 12, label %69
    i32 11, label %75
    i32 10, label %82
    i32 9, label %89
    i32 8, label %95
    i32 7, label %102
    i32 6, label %110
    i32 5, label %118
    i32 4, label %125
    i32 3, label %133
    i32 2, label %142
    i32 1, label %151
  ]

; <label>:69:                                     ; preds = %63
  %70 = getelementptr inbounds i8, i8* %68, i64 11
  %71 = load i8, i8* %70, align 1, !tbaa !7
  %72 = zext i8 %71 to i32
  %73 = shl nuw i32 %72, 24
  %74 = add i32 %73, %67
  br label %75

; <label>:75:                                     ; preds = %63, %69
  %76 = phi i32 [ %67, %63 ], [ %74, %69 ]
  %77 = getelementptr inbounds i8, i8* %68, i64 10
  %78 = load i8, i8* %77, align 1, !tbaa !7
  %79 = zext i8 %78 to i32
  %80 = shl nuw nsw i32 %79, 16
  %81 = add i32 %80, %76
  br label %82

; <label>:82:                                     ; preds = %63, %75
  %83 = phi i32 [ %67, %63 ], [ %81, %75 ]
  %84 = getelementptr inbounds i8, i8* %68, i64 9
  %85 = load i8, i8* %84, align 1, !tbaa !7
  %86 = zext i8 %85 to i32
  %87 = shl nuw nsw i32 %86, 8
  %88 = add i32 %87, %83
  br label %89

; <label>:89:                                     ; preds = %63, %82
  %90 = phi i32 [ %67, %63 ], [ %88, %82 ]
  %91 = getelementptr inbounds i8, i8* %68, i64 8
  %92 = load i8, i8* %91, align 1, !tbaa !7
  %93 = zext i8 %92 to i32
  %94 = add i32 %90, %93
  br label %95

; <label>:95:                                     ; preds = %63, %89
  %96 = phi i32 [ %67, %63 ], [ %94, %89 ]
  %97 = getelementptr inbounds i8, i8* %68, i64 7
  %98 = load i8, i8* %97, align 1, !tbaa !7
  %99 = zext i8 %98 to i32
  %100 = shl nuw i32 %99, 24
  %101 = add i32 %100, %66
  br label %102

; <label>:102:                                    ; preds = %63, %95
  %103 = phi i32 [ %66, %63 ], [ %101, %95 ]
  %104 = phi i32 [ %67, %63 ], [ %96, %95 ]
  %105 = getelementptr inbounds i8, i8* %68, i64 6
  %106 = load i8, i8* %105, align 1, !tbaa !7
  %107 = zext i8 %106 to i32
  %108 = shl nuw nsw i32 %107, 16
  %109 = add i32 %108, %103
  br label %110

; <label>:110:                                    ; preds = %63, %102
  %111 = phi i32 [ %66, %63 ], [ %109, %102 ]
  %112 = phi i32 [ %67, %63 ], [ %104, %102 ]
  %113 = getelementptr inbounds i8, i8* %68, i64 5
  %114 = load i8, i8* %113, align 1, !tbaa !7
  %115 = zext i8 %114 to i32
  %116 = shl nuw nsw i32 %115, 8
  %117 = add i32 %116, %111
  br label %118

; <label>:118:                                    ; preds = %63, %110
  %119 = phi i32 [ %66, %63 ], [ %117, %110 ]
  %120 = phi i32 [ %67, %63 ], [ %112, %110 ]
  %121 = getelementptr inbounds i8, i8* %68, i64 4
  %122 = load i8, i8* %121, align 1, !tbaa !7
  %123 = zext i8 %122 to i32
  %124 = add i32 %119, %123
  br label %125

; <label>:125:                                    ; preds = %63, %118
  %126 = phi i32 [ %66, %63 ], [ %124, %118 ]
  %127 = phi i32 [ %67, %63 ], [ %120, %118 ]
  %128 = getelementptr inbounds i8, i8* %68, i64 3
  %129 = load i8, i8* %128, align 1, !tbaa !7
  %130 = zext i8 %129 to i32
  %131 = shl nuw i32 %130, 24
  %132 = add i32 %131, %65
  br label %133

; <label>:133:                                    ; preds = %63, %125
  %134 = phi i32 [ %65, %63 ], [ %132, %125 ]
  %135 = phi i32 [ %66, %63 ], [ %126, %125 ]
  %136 = phi i32 [ %67, %63 ], [ %127, %125 ]
  %137 = getelementptr inbounds i8, i8* %68, i64 2
  %138 = load i8, i8* %137, align 1, !tbaa !7
  %139 = zext i8 %138 to i32
  %140 = shl nuw nsw i32 %139, 16
  %141 = add i32 %140, %134
  br label %142

; <label>:142:                                    ; preds = %63, %133
  %143 = phi i32 [ %65, %63 ], [ %141, %133 ]
  %144 = phi i32 [ %66, %63 ], [ %135, %133 ]
  %145 = phi i32 [ %67, %63 ], [ %136, %133 ]
  %146 = getelementptr inbounds i8, i8* %68, i64 1
  %147 = load i8, i8* %146, align 1, !tbaa !7
  %148 = zext i8 %147 to i32
  %149 = shl nuw nsw i32 %148, 8
  %150 = add i32 %149, %143
  br label %151

; <label>:151:                                    ; preds = %63, %142
  %152 = phi i32 [ %65, %63 ], [ %150, %142 ]
  %153 = phi i32 [ %66, %63 ], [ %144, %142 ]
  %154 = phi i32 [ %67, %63 ], [ %145, %142 ]
  %155 = load i8, i8* %68, align 1, !tbaa !7
  %156 = zext i8 %155 to i32
  %157 = add i32 %152, %156
  %158 = xor i32 %154, %153
  %159 = shl i32 %153, 14
  %160 = lshr i32 %153, 18
  %161 = or i32 %160, %159
  %162 = sub i32 %158, %161
  %163 = xor i32 %157, %162
  %164 = shl i32 %162, 11
  %165 = lshr i32 %162, 21
  %166 = or i32 %165, %164
  %167 = sub i32 %163, %166
  %168 = xor i32 %167, %153
  %169 = shl i32 %167, 25
  %170 = lshr i32 %167, 7
  %171 = or i32 %170, %169
  %172 = sub i32 %168, %171
  %173 = xor i32 %172, %162
  %174 = shl i32 %172, 16
  %175 = lshr i32 %172, 16
  %176 = or i32 %175, %174
  %177 = sub i32 %173, %176
  %178 = xor i32 %177, %167
  %179 = shl i32 %177, 4
  %180 = lshr i32 %177, 28
  %181 = or i32 %180, %179
  %182 = sub i32 %178, %181
  %183 = xor i32 %182, %172
  %184 = shl i32 %182, 14
  %185 = lshr i32 %182, 18
  %186 = or i32 %185, %184
  %187 = sub i32 %183, %186
  %188 = xor i32 %187, %177
  %189 = shl i32 %187, 24
  %190 = lshr i32 %187, 8
  %191 = or i32 %190, %189
  %192 = sub i32 %188, %191
  br label %193

; <label>:193:                                    ; preds = %63, %151
  %194 = phi i32 [ %67, %63 ], [ %192, %151 ]
  ret i32 %194
}

attributes #0 = { inlinehint norecurse nounwind readonly uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-frame-pointer-elim"="false" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 8.0.1-svn363027-1~exp1~20190611211629.77 (branches/release_80)"}
!2 = !{!3, !4, i64 0}
!3 = !{!"__una_u32", !4, i64 0}
!4 = !{!"int", !5, i64 0}
!5 = !{!"omnipotent char", !6, i64 0}
!6 = !{!"Simple C/C++ TBAA"}
!7 = !{!5, !5, i64 0}
