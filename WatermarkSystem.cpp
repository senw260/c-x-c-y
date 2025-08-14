#include <opencv2/opencv.hpp>
#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/highgui.hpp>
#include <random>
#include <iostream>
#include <string>
#include <map>
#include <cmath>

using namespace cv;
using namespace std;

class WatermarkSystem {
private:
    Size watermarkSize;
    double alpha;
    unsigned int key;
    mt19937 rng;

public:
    // 构造函数
    WatermarkSystem(Size size = Size(32, 32), double a = 0.05)
        : watermarkSize(size), alpha(a) {
        random_device rd;
        key = rd();
        rng.seed(key);
    }

    // 生成水印
    Mat generateWatermark(const string& message = "") {
        Mat watermark(watermarkSize, CV_8UC1);

        if (!message.empty()) {
            // 基于消息生成水印
            hash<string> hashFunc;
            size_t hashVal = hashFunc(message);
            rng.seed(hashVal);
        }
        else {
            // 生成随机水印
            rng.seed(key);
        }

        uniform_int_distribution<int> dist(0, 1);
        for (int i = 0; i < watermark.rows; ++i) {
            for (int j = 0; j < watermark.cols; ++j) {
                watermark.at<uchar>(i, j) = dist(rng) * 255;
            }
        }

        return watermark;
    }

    // 嵌入水印
    Mat embedWatermark(const string& imagePath, const Mat& watermark, const string& outputPath = "") {
        Mat image = imread(imagePath);
        if (image.empty()) {
            throw runtime_error("无法读取图像，请检查路径是否正确");
        }

        // 转换为YCrCb颜色空间
        Mat ycrcbImage;
        cvtColor(image, ycrcbImage, COLOR_BGR2YCrCb);

        // 分离通道，只在Y通道嵌入水印
        vector<Mat> channels;
        split(ycrcbImage, channels);
        Mat yChannel = channels[0].clone();
        yChannel.convertTo(yChannel, CV_32FC1);

        int h = yChannel.rows;
        int w = yChannel.cols;
        int wh = watermark.rows;
        int ww = watermark.cols;

        // 对每个8x8块进行DCT变换并嵌入水印
        for (int i = 0; i < h; i += 8) {
            for (int j = 0; j < w; j += 8) {
                // 确保块大小为8x8
                if (i + 8 > h || j + 8 > w) continue;

                Mat block = yChannel(Rect(j, i, 8, 8));
                Mat dctBlock;

                // DCT变换
                dct(block, dctBlock);

                // 嵌入水印
                int wi = (i / 8) % wh;
                int wj = (j / 8) % ww;
                uchar wmVal = watermark.at<uchar>(wi, wj);
                dctBlock.at<float>(5, 5) += alpha * (wmVal > 0 ? 1 : -1);

                // 逆DCT变换
                idct(dctBlock, block);
            }
        }

        // 合并通道并转换回BGR
        yChannel.convertTo(channels[0], CV_8UC1);
        merge(channels, ycrcbImage);
        Mat watermarkedImage;
        cvtColor(ycrcbImage, watermarkedImage, COLOR_YCrCb2BGR);

        // 保存图像
        if (!outputPath.empty()) {
            imwrite(outputPath, watermarkedImage);
        }

        return watermarkedImage;
    }

    // 提取水印
    Mat extractWatermark(const string& originalImagePath, const Mat& watermarkedImage, double threshold = 0.0) {
        Mat originalImage = imread(originalImagePath);
        if (originalImage.empty()) {
            throw runtime_error("无法读取原始图像，请检查路径是否正确");
        }

        // 转换为YCrCb颜色空间
        Mat originalYCrCb, watermarkedYCrCb;
        cvtColor(originalImage, originalYCrCb, COLOR_BGR2YCrCb);
        cvtColor(watermarkedImage, watermarkedYCrCb, COLOR_BGR2YCrCb);

        // 提取Y通道
        vector<Mat> originalChannels, watermarkedChannels;
        split(originalYCrCb, originalChannels);
        split(watermarkedYCrCb, watermarkedChannels);

        Mat originalY = originalChannels[0].clone();
        Mat watermarkedY = watermarkedChannels[0].clone();

        originalY.convertTo(originalY, CV_32FC1);
        watermarkedY.convertTo(watermarkedY, CV_32FC1);

        int h = originalY.rows;
        int w = originalY.cols;

        // 初始化提取的水印
        Mat extractedWatermark(watermarkSize, CV_8UC1, Scalar(0));

        // 提取水印
        for (int i = 0; i < h; i += 8) {
            for (int j = 0; j < w; j += 8) {
                // 确保块大小为8x8
                if (i + 8 > h || j + 8 > w) continue;

                Mat originalBlock = originalY(Rect(j, i, 8, 8));
                Mat watermarkedBlock = watermarkedY(Rect(j, i, 8, 8));

                Mat originalDCT, watermarkedDCT;
                dct(originalBlock, originalDCT);
                dct(watermarkedBlock, watermarkedDCT);

                // 计算差异
                double diff = watermarkedDCT.at<float>(5, 5) - originalDCT.at<float>(5, 5);

                // 确定水印位置
                int wi = (i / 8) % watermarkSize.height;
                int wj = (j / 8) % watermarkSize.width;

                // 二值化
                extractedWatermark.at<uchar>(wi, wj) = (diff > threshold) ? 255 : 0;
            }
        }

        return extractedWatermark;
    }

    // 计算水印相似度
    double calculateSimilarity(const Mat& original, const Mat& extracted) {
        if (original.size() != extracted.size() || original.type() != extracted.type()) {
            throw invalid_argument("水印尺寸或类型不匹配");
        }

        int total = original.total();
        int matches = 0;

        for (int i = 0; i < original.rows; ++i) {
            for (int j = 0; j < original.cols; ++j) {
                if (original.at<uchar>(i, j) == extracted.at<uchar>(i, j)) {
                    matches++;
                }
            }
        }

        return (static_cast<double>(matches) / total) * 100;
    }

    // 图像处理函数 - 用于鲁棒性测试
    Mat flipImage(const Mat& image, int flipCode) {
        Mat result;
        flip(image, result, flipCode);
        return result;
    }

    Mat translateImage(const Mat& image, int x, int y) {
        Mat result;
        Mat translation = (Mat_<double>(2, 3) << 1, 0, x, 0, 1, y);
        warpAffine(image, result, translation, image.size());
        return result;
    }

    Mat cropImage(const Mat& image, int x1, int y1, int x2, int y2) {
        return image(Rect(x1, y1, x2 - x1, y2 - y1)).clone();
    }

    Mat adjustContrast(const Mat& image, double alpha, int beta = 0) {
        Mat result;
        image.convertTo(result, -1, alpha, beta);
        return result;
    }

    Mat addNoise(const Mat& image, double mean = 0, double var = 0.001) {
        Mat result, imageFloat;
        image.convertTo(imageFloat, CV_32FC3);
        imageFloat /= 255.0;

        Mat noise(image.size(), CV_32FC3);
        randn(noise, mean, sqrt(var));

        result = imageFloat + noise;
        result = min(result, 1.0);
        result = max(result, 0.0);
        result *= 255.0;
        result.convertTo(result, CV_8UC3);

        return result;
    }

    Mat rotateImage(const Mat& image, double angle) {
        Mat result;
        Point2f center(image.cols / 2.0f, image.rows / 2.0f);
        Mat rotation = getRotationMatrix2D(center, angle, 1.0);
        warpAffine(image, result, rotation, image.size());
        return result;
    }

    // 执行鲁棒性测试
    map<string, double> performRobustnessTests(const string& originalImagePath,
        const Mat& watermarkedImage,
        const Mat& originalWatermark) {
        map<string, Mat> tests;

        // 添加各种测试情况
        tests["原始图像"] = watermarkedImage;
        tests["水平翻转"] = flipImage(watermarkedImage, 1);
        tests["垂直翻转"] = flipImage(watermarkedImage, 0);
        tests["平移(50,30)"] = translateImage(watermarkedImage, 50, 30);

        // 裁剪10%边框
        int x1 = watermarkedImage.cols * 0.1;
        int y1 = watermarkedImage.rows * 0.1;
        int x2 = watermarkedImage.cols * 0.9;
        int y2 = watermarkedImage.rows * 0.9;
        tests["裁剪(10%,10%,90%,90%)"] = cropImage(watermarkedImage, x1, y1, x2, y2);

        tests["高对比度(2.0)"] = adjustContrast(watermarkedImage, 2.0);
        tests["低对比度(0.5)"] = adjustContrast(watermarkedImage, 0.5);
        tests["高斯噪声"] = addNoise(watermarkedImage);
        tests["旋转(30度)"] = rotateImage(watermarkedImage, 30);

        map<string, double> results;

        // 创建窗口显示结果
        namedWindow("测试结果", WINDOW_NORMAL);
        resizeWindow("测试结果", 1200, 800);

        Mat display(800, 1200, CV_8UC3, Scalar(255, 255, 255));
        int y = 20;
        int x = 20;

        // 显示原始水印
        putText(display, "原始水印", Point(x, y - 5), FONT_HERSHEY_SIMPLEX, 0.5, Scalar(0, 0, 0), 1);
        Mat resizedWatermark;
        resize(originalWatermark, resizedWatermark, Size(150, 150));
        cvtColor(resizedWatermark, resizedWatermark, COLOR_GRAY2BGR);
        resizedWatermark.copyTo(display(Rect(x, y, 150, 150)));
        x += 170;

        // 处理每个测试情况
        int count = 0;
        for (auto& pair : tests) {
            try {
                // 提取水印
                Mat extracted = extractWatermark(originalImagePath, pair.second);
                double similarity = calculateSimilarity(originalWatermark, extracted);
                results[pair.first] = similarity;

                // 显示处理后的图像
                if (x + 150 > 1200) {
                    x = 20;
                    y += 170;
                }

                putText(display, pair.first, Point(x, y - 5), FONT_HERSHEY_SIMPLEX, 0.5, Scalar(0, 0, 0), 1);
                Mat resized;
                resize(pair.second, resized, Size(150, 150));
                resized.copyTo(display(Rect(x, y, 150, 150)));
                x += 170;

                // 显示提取的水印和相似度
                putText(display, format("相似度: %.2f%%", similarity), Point(x, y - 5),
                    FONT_HERSHEY_SIMPLEX, 0.5, Scalar(0, 0, 0), 1);
                Mat resizedExtracted;
                resize(extracted, resizedExtracted, Size(150, 150));
                cvtColor(resizedExtracted, resizedExtracted, COLOR_GRAY2BGR);
                resizedExtracted.copyTo(display(Rect(x, y, 150, 150)));
                x += 170;

                count++;
                if (count >= 4) break; // 限制显示数量，避免窗口过大
            }
            catch (const exception& e) {
                cerr << "测试 " << pair.first << " 失败: " << e.what() << endl;
                results[pair.first] = -1;
            }
        }

        imshow("测试结果", display);
        waitKey(0);

        return results;
    }
};

int main() {
    try {
        // 创建水印系统实例
        WatermarkSystem watermarkSystem(Size(32, 32), 0.08);

        // 生成水印
        Mat watermark = watermarkSystem.generateWatermark("MySecretWatermark123");

        // 嵌入水印
        string originalImagePath = "original_image.jpg"; // 替换为你的图像路径
        Mat watermarkedImage = watermarkSystem.embedWatermark(originalImagePath, watermark, "watermarked_image.jpg");
        cout << "水印嵌入成功！" << endl;

        // 提取水印并计算相似度
        Mat extractedWatermark = watermarkSystem.extractWatermark(originalImagePath, watermarkedImage);
        double similarity = watermarkSystem.calculateSimilarity(watermark, extractedWatermark);
        cout << "原始图像水印提取相似度: " << fixed << setprecision(2) << similarity << "%" << endl;

        // 显示原始水印和提取的水印
        namedWindow("水印对比", WINDOW_NORMAL);
        Mat watermarkDisplay(180, 340, CV_8UC3, Scalar(255, 255, 255));
        putText(watermarkDisplay, "原始水印", Point(10, 15), FONT_HERSHEY_SIMPLEX, 0.5, Scalar(0, 0, 0), 1);
        Mat resizedOrig, resizedExt;
        resize(watermark, resizedOrig, Size(150, 150));
        cvtColor(resizedOrig, resizedOrig, COLOR_GRAY2BGR);
        resizedOrig.copyTo(watermarkDisplay(Rect(10, 20, 150, 150)));

        putText(watermarkDisplay, format("提取的水印 (相似度: %.2f%%)", similarity),
            Point(180, 15), FONT_HERSHEY_SIMPLEX, 0.5, Scalar(0, 0, 0), 1);
        resize(extractedWatermark, resizedExt, Size(150, 150));
        cvtColor(resizedExt, resizedExt, COLOR_GRAY2BGR);
        resizedExt.copyTo(watermarkDisplay(Rect(180, 20, 150, 150)));

        imshow("水印对比", watermarkDisplay);
        waitKey(0);

        // 执行鲁棒性测试
        cout << "\n开始鲁棒性测试..." << endl;
        map<string, double> testResults = watermarkSystem.performRobustnessTests(
            originalImagePath, watermarkedImage, watermark);

        // 打印所有测试结果
        cout << "\n鲁棒性测试结果:" << endl;
        for (auto& pair : testResults) {
            if (pair.second == -1) {
                cout << pair.first << ": 失败" << endl;
            }
            else {
                cout << pair.first << ": " << fixed << setprecision(2) << pair.second << "%" << endl;
            }
        }

    }
    catch (const exception& e) {
        cerr << "发生错误: " << e.what() << endl;
        return 1;
    }

    return 0;
}
