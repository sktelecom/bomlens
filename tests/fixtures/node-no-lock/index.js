/**
 * SBOM Example Application - Express.js API
 * 
 * 간단한 Express 기반 REST API 애플리케이션입니다.
 * SBOM 생성 테스트를 위한 예제입니다.
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const _ = require('lodash');
const moment = require('moment');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// 미들웨어 설정
app.use(helmet()); // 보안 헤더
app.use(cors()); // CORS 활성화
app.use(compression()); // 응답 압축
app.use(morgan('combined')); // 로깅
app.use(express.json()); // JSON 파싱
app.use(express.urlencoded({ extended: true })); // URL 인코딩 파싱

// 메인 엔드포인트
app.get('/', (req, res) => {
  res.json({
    message: 'SBOM Example Application is running!',
    version: '1.0.0',
    timestamp: moment().format(),
    framework: 'Express.js'
  });
});

// 헬스 체크
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK',
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});

// 샘플 데이터 엔드포인트
app.get('/data', (req, res) => {
  const sampleData = _.range(1, 11).map(id => ({
    id,
    value: _.random(0, 100),
    label: `Item ${id}`,
    timestamp: moment().subtract(id, 'days').format()
  }));

  res.json({
    data: sampleData,
    count: sampleData.length
  });
});

// 데이터 분석 엔드포인트
app.post('/analyze', (req, res) => {
  const { numbers } = req.body;

  if (!numbers || !Array.isArray(numbers)) {
    return res.status(400).json({ 
      error: 'numbers array is required' 
    });
  }

  const result = {
    mean: _.mean(numbers),
    sum: _.sum(numbers),
    min: _.min(numbers),
    max: _.max(numbers),
    count: numbers.length
  };

  res.json(result);
});

// 유틸리티 엔드포인트
app.get('/utils/date', (req, res) => {
  const { format = 'YYYY-MM-DD HH:mm:ss' } = req.query;
  
  res.json({
    current: moment().format(format),
    utc: moment.utc().format(format),
    unix: moment().unix(),
    iso: moment().toISOString()
  });
});

// 에러 핸들링 미들웨어
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: err.message 
  });
});

// 404 핸들러
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Not Found',
    path: req.path 
  });
});

// 서버 시작
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Visit: http://localhost:${PORT}`);
});

module.exports = app;
